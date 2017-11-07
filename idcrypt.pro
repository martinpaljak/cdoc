-injars target/cdoc.jar
-libraryjars  <java.home>/lib/rt.jar
-libraryjars  <java.home>/lib/jce.jar
-outjars cdoc.jar
-dontobfuscate
-dontoptimize
-keep public class org.esteid.cdoc.Tool {
    public static void main(java.lang.String[]);
}
-dontnote
-dontwarn
