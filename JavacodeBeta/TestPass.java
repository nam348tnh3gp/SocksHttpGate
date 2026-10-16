public class TestPass {
    public static void main(String[] args) throws Exception {
        String pwd = "admin12345";
        String h = Proxy.hashPassword(pwd);
        System.out.println("hash: " + h);
        System.out.println("verify correct: " + Proxy.verifyPassword(pwd, h));
        System.out.println("verify wrong: " + Proxy.verifyPassword("wrong", h));
    }
}
