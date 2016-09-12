-injars build
-injars lib/bcprov-jdk15on-155.jar(!META-INF/**)
-injars lib/bcpkix-jdk15on-155.jar(!META-INF/**)
-injars lib/jopt-simple-5.0.2.jar(!META-INF/**)
-injars lib/esteid.jar
-dontwarn org.esteid.hacker.**
#-injars lib/slf4j-api-1.7.13.jar(!META-INF/**)
#-dontwarn org.slf4j.**
# these are library because we package everything back in
#-libraryjars lib/slf4j-simple-1.7.13.jar
-libraryjars lib/apdu4j.jar
-libraryjars  <java.home>/lib/rt.jar
-libraryjars  <java.home>/lib/jce.jar
-outjars optimized-idcrypt.jar
-dontobfuscate
-dontoptimize
-keep public class org.esteid.crypt.Tool {
    public static void main(java.lang.String[]);
}
-printseeds
-dontnote
