package main
import(
 "bytes";"context";"crypto/subtle";"encoding/hex";"encoding/json";"errors";"io";"log";"net/http";"net/url";"os";"strings";"sync";"sync/atomic";"time"
 odoh "github.com/cloudflare/odoh-go";"github.com/miekg/dns"
)
const(odohType="application/oblivious-dns-message";dnsType="application/dns-message";maxBody=65535;maxList=10<<20)
type target struct{kp odoh.ObliviousDoHKeyPair;client *http.Client;upstream string;mu sync.RWMutex;blocked map[string]struct{};sources []string;refresh time.Duration;started time.Time;queries,blockedQueries,errors atomic.Uint64}
func main(){
 seed,e:=hex.DecodeString(strings.TrimSpace(os.Getenv("ODOH_KEY_SEED")));if e!=nil||len(seed)!=32{log.Fatal("ODOH_KEY_SEED must be a persistent 32-byte seed (64 hex chars); generate with openssl rand -hex 32")}
 kp,e:=odoh.CreateDefaultKeyPairFromSeed(seed);if e!=nil{log.Fatalf("ODoH key: %v",e)}
 upstream:=env("UPSTREAM_DOH","https://cloudflare-dns.com/dns-query");u,e:=url.Parse(upstream);if e!=nil||u.Scheme!="https"||u.Host==""||u.User!=nil||u.Fragment!=""{log.Fatal("UPSTREAM_DOH must be an HTTPS URL")}
 refresh:=6*time.Hour;if v:=os.Getenv("BLOCKLIST_REFRESH");v!=""{refresh,e=time.ParseDuration(v);if e!=nil||refresh<time.Minute{log.Fatal("BLOCKLIST_REFRESH must be at least 1m")}}
 t:=&target{kp:kp,upstream:upstream,client:&http.Client{Timeout:8*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}},blocked:parseInline(os.Getenv("BLOCKLIST")),sources:parseSources(os.Getenv("BLOCKLIST_URLS")),refresh:refresh,started:time.Now()}
 if len(t.sources)>0{t.refreshLists();go t.refreshLoop()}
 mux:=http.NewServeMux();mux.HandleFunc("/health",t.health);mux.HandleFunc("/api/stats",t.stats);mux.HandleFunc("/api/v1/health",t.health);mux.HandleFunc("/api/v1/stats",t.stats);mux.HandleFunc("/api/v1/status",t.apiStatus);mux.HandleFunc("/.well-known/odohconfigs",t.configs);mux.HandleFunc("/proxy",t.query)
 srv:=&http.Server{Addr:env("ADDR",":"+env("PORT","8080")),Handler:secureHeaders(mux),ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:12*time.Second,IdleTimeout:60*time.Second,MaxHeaderBytes:16<<10}
 log.Printf("ODoH Target started; remote_blocklist_sources=%d; per-query logging disabled",len(t.sources));log.Fatal(srv.ListenAndServe())
}
func(t *target)configs(w http.ResponseWriter,r *http.Request){if r.Method!="GET"{http.Error(w,"method not allowed",405);return};w.Header().Set("Content-Type","application/octet-stream");w.Header().Set("Cache-Control","public, max-age=300");_,_=w.Write(odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{t.kp.Config}).Marshal())}
func(t *target)query(w http.ResponseWriter,r *http.Request){
 // The archived odoh-go parser has unchecked length reads in its message-body decoder.
 // A malicious client can craft an authenticated, malformed ODoH plaintext that panics it.
 // Recover per request so one malformed message cannot terminate the Target process.
 defer func(){if r:=recover();r!=nil{t.errors.Add(1);log.Printf("recovered panic in /proxy: %v",r);http.Error(w,"invalid ODoH message",400)}}()
 if r.Method!="POST"{http.Error(w,"method not allowed",405);return};if mediaType(r.Header.Get("Content-Type"))!=odohType{http.Error(w,"unsupported media type",415);return}
 raw,e:=io.ReadAll(http.MaxBytesReader(w,r.Body,maxBody));if e!=nil{http.Error(w,"invalid request body",400);return}
 msg,e:=odoh.UnmarshalDNSMessage(raw);kid:=t.kp.Config.Contents.KeyID()
 if e!=nil||len(msg.KeyID)!=len(kid)||subtle.ConstantTimeCompare(msg.KeyID,kid)!=1||len(msg.EncryptedMessage)<64{t.errors.Add(1);http.Error(w,"invalid ODoH message",400);return}
 qb,ctx,e:=t.kp.DecryptQuery(msg);if e!=nil{t.errors.Add(1);http.Error(w,"unable to decrypt ODoH message",400);return}
 if len(qb.DnsMessage)<12||len(qb.DnsMessage)>4096{t.errors.Add(1);http.Error(w,"invalid DNS message",400);return}
 q:=new(dns.Msg);if e=q.Unpack(qb.DnsMessage);e!=nil||len(q.Question)!=1{t.errors.Add(1);http.Error(w,"invalid DNS query",400);return};t.queries.Add(1)
 var answer []byte
 if t.isBlocked(q.Question[0].Name){reply:=new(dns.Msg);reply.SetReply(q);reply.Rcode=dns.RcodeNameError;reply.Authoritative=true;if soa,se:=dns.NewRR("blocked.invalid. 60 IN SOA localhost. hostmaster.localhost. 1 3600 600 604800 60");se==nil{reply.Ns=[]dns.RR{soa}};answer,e=reply.Pack();t.blockedQueries.Add(1)}else{answer,e=t.resolve(r.Context(),qb.DnsMessage)}
 if e!=nil||len(answer)==0||len(answer)>4096{t.errors.Add(1);http.Error(w,"DNS resolution failed",502);return}
 out,e:=ctx.EncryptResponse(odoh.CreateObliviousDNSResponse(answer,0));if e!=nil{t.errors.Add(1);http.Error(w,"response encryption failed",500);return}
 w.Header().Set("Content-Type",odohType);w.Header().Set("Cache-Control","no-store");_,_=w.Write(out.Marshal())
}
func(t *target)resolve(ctx context.Context,wire []byte)([]byte,error){req,e:=http.NewRequestWithContext(ctx,"POST",t.upstream,bytes.NewReader(wire));if e!=nil{return nil,e};req.Header.Set("Content-Type",dnsType);req.Header.Set("Accept",dnsType);resp,e:=t.client.Do(req);if e!=nil{return nil,e};defer resp.Body.Close();if resp.StatusCode!=200||mediaType(resp.Header.Get("Content-Type"))!=dnsType{return nil,errors.New("upstream rejected DNS query")};b,e:=io.ReadAll(io.LimitReader(resp.Body,4097));if e!=nil||len(b)==0||len(b)>4096{return nil,errors.New("invalid upstream DNS response")};return b,nil}
func(t *target)refreshLoop(){ticker:=time.NewTicker(t.refresh);defer ticker.Stop();for range ticker.C{t.refreshLists()}}
func(t *target)refreshLists(){next:=parseInline(os.Getenv("BLOCKLIST"));success:=0;for _,src:=range t.sources{ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second);req,e:=http.NewRequestWithContext(ctx,"GET",src,nil);if e==nil{resp,x:=t.client.Do(req);if x==nil{if resp.StatusCode==200{b,re:=io.ReadAll(io.LimitReader(resp.Body,maxList+1));if re==nil&&len(b)>0&&len(b)<=maxList{before:=len(next);addHosts(next,string(b));if len(next)>before{success++}}};resp.Body.Close()}};cancel()};if success==0{t.mu.RLock();previous:=len(t.blocked);t.mu.RUnlock();if previous>0{log.Printf("blocklist refresh failed; keeping last-known-good list (%d domains)",previous);return}};t.mu.Lock();t.blocked=next;t.mu.Unlock();log.Printf("blocklist refreshed; active_domains=%d; successful_sources=%d/%d",len(next),success,len(t.sources))}
func(t *target)isBlocked(name string)bool{t.mu.RLock();defer t.mu.RUnlock();for d:=norm(name);d!="";{if _,ok:=t.blocked[d];ok{return true};i:=strings.IndexByte(d,'.');if i<0{break};d=d[i+1:]};return false}
func(t *target)health(w http.ResponseWriter,r *http.Request){if r.Method!="GET"{http.Error(w,"method not allowed",405);return};w.Header().Set("Content-Type","text/plain");_,_=io.WriteString(w,"ok\n")}
func(t *target)apiStatus(w http.ResponseWriter,r *http.Request){if r.Method!="GET"{http.Error(w,"method not allowed",405);return};w.Header().Set("Content-Type","application/json");w.Header().Set("Cache-Control","no-store");_=json.NewEncoder(w).Encode(map[string]any{"service":"odoh-target","status":"running","protocol":"RFC 9230 ODoH","uptime_seconds":int64(time.Since(t.started).Seconds())})}
func(t *target)stats(w http.ResponseWriter,r *http.Request){if r.Method!="GET"{http.Error(w,"method not allowed",405);return};t.mu.RLock();n:=len(t.blocked);t.mu.RUnlock();w.Header().Set("Content-Type","application/json");w.Header().Set("Cache-Control","no-store");_=json.NewEncoder(w).Encode(map[string]any{"ready":true,"uptime_seconds":int64(time.Since(t.started).Seconds()),"queries":t.queries.Load(),"blocked_queries":t.blockedQueries.Load(),"errors":t.errors.Load(),"blocked_domains":n,"blocklist_sources":len(t.sources),"privacy_mode":"aggregate only; no query/domain/client logging"})}
func parseInline(raw string)map[string]struct{}{m:=map[string]struct{}{};for _,v:=range strings.FieldsFunc(raw,sep){d:=norm(v);if valid(d){m[d]=struct{}{}}};return m}
func parseSources(raw string)[]string{var out []string;for _,v:=range strings.FieldsFunc(raw,sep){u,e:=url.Parse(strings.TrimSpace(v));if e==nil&&u.Scheme=="https"&&u.Host!=""&&u.User==nil&&u.Fragment==""{out=append(out,u.String())}};return out}
func addHosts(m map[string]struct{},s string){for _,line:=range strings.Split(s,"\n"){f:=strings.Fields(strings.SplitN(line,"#",2)[0]);if len(f)==0{continue};if len(f)>1&&(f[0]=="0.0.0.0"||f[0]=="127.0.0.1"||f[0]=="::"||f[0]=="::1"){for _,v:=range f[1:]{d:=norm(v);if valid(d){m[d]=struct{}{}}};continue};d:=norm(f[0]);if valid(d){m[d]=struct{}{}}}}
func sep(r rune)bool{return r==','||r==';'||r=='\n'||r=='\r'||r==' '||r=='\t'}
func norm(s string)string{return strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)),"*."),".")}
func valid(s string)bool{if s==""||len(s)>253||strings.ContainsAny(s,"/:*")||strings.Contains(s,".."){return false};_,ok:=dns.IsDomainName(s+".");return ok}
func mediaType(s string)string{return strings.ToLower(strings.TrimSpace(strings.SplitN(s,";",2)[0]))}
func secureHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("Cache-Control","no-store");next.ServeHTTP(w,r)})}
func env(k,d string)string{if v:=strings.TrimSpace(os.Getenv(k));v!=""{return v};return d}
