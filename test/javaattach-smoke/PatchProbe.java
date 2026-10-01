package smoke;

public final class PatchProbe {
    public static String status() { return "VULNERABLE"; }

    public static void main(String[] args) throws Exception {
        for (;;) {
            System.out.println(status());
            System.out.flush();
            Thread.sleep(250);
        }
    }
}
