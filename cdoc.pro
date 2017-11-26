-injars target/cdoc.jar
-libraryjars  <java.home>/lib/rt.jar
-libraryjars  <java.home>/lib/jce.jar
-outjars cdoc.jar
-dontobfuscate
-dontoptimize
-keep public class org.cdoc4j.cli.Tool {
    public static void main(java.lang.String[]);
}

-keep class com.sun.jna.** { *; }
-keep class jnasmartcardio.** { *; }
-dontnote
-dontwarn
