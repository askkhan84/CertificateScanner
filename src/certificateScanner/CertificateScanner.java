/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 * @author Ahmed Khan
 */
package certificateScanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.net.InetAddress;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.StringTokenizer;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.net.util.SubnetUtils;

public class CertificateScanner {

    public static FileWriter fw;
    public static FileWriter fw1;
    public static SimpleDateFormat sdf = new SimpleDateFormat("dd-MMM-YYYY");
    public static Date d = new Date();
    static String ports;

    public static void main(String[] args) {
        CertificateScanner tester = new CertificateScanner();
        try {
            if (args.length == 6) {
                String inputFile = args[0];
                String outputFile = args[1];
                String errorFilename = args[2];
                String portFileName = args[3];
                boolean chainValidation = Boolean.valueOf(args[4]);
                int months = Integer.valueOf(args[5]);
                tester.testConnectionTo(inputFile, outputFile, errorFilename, portFileName, chainValidation, months);
            } else {
                System.out.println("Usage: CertificateValidationChecker inputFilePath outputFilePath errorFilePath portsFilePath validateChain(true|false) monthsToExpiry ");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void testConnectionTo(String inputFileName, String outputFile, String errorFilename, String portFileName, boolean validateChain, int months) throws Exception {
        d = new Date();
        d.setMonth(d.getMonth() + months);
        sdf = new SimpleDateFormat("dd-MMM-YYYY");
        String strURL = null;
        fw = new FileWriter(outputFile);
        File f = new File(inputFileName);
        File portsF = new File(portFileName);

        fw1 = new FileWriter(errorFilename);

        BufferedReader b = new BufferedReader(new FileReader(f));
        BufferedReader portBR = new BufferedReader(new FileReader(portsF));
        ports = portBR.readLine();
        System.out.println("Checking if certs will be expired by:" + sdf.format(d));
        fw.write("Target Expiry Date:" + sdf.format(d) + System.getProperty("line.separator"));
        String readLine = "";
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }};
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HostnameVerifier allHostsValid = new HostnameVerifier() {

            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        SubnetUtils su = null;
        block7:
        while ((readLine = b.readLine()) != null) {
            try {

                Certificate[] certs;
                //strURL = readLine;
                String[] range = null;
                try {
                    su = new SubnetUtils(readLine);
                    range = su.getInfo().getAllAddresses();
                } catch (Exception e) {
                    fw1.write(readLine + " - not subnet..assuming single IP or DNS/Domain entry" + System.getProperty("line.separator"));
                    su = null;
                    range = null;
                }

                if (su != null) {
                    for (int i = 0; i < range.length; i++) {
                        strURL = range[i];
                        checkURL(strURL, validateChain);
                    }
                } else {
                    strURL = readLine;
                    checkURL(strURL, validateChain);
                }
                fw.flush();
                fw1.flush();

            } catch (Exception e) {
                if (e.getMessage().contains("PKIX path building failed")) {
                    fw1.write("CHEC:" + strURL + "," + strURL + ": Self signed or root cert not trusted. Check manually" + System.getProperty("line.separator"));
                    continue;
                }
                fw1.write("Error checking URL:" + strURL + " Error:" + e.getMessage() + System.getProperty("line.separator"));
                fw.flush();
                fw1.flush();
                e.printStackTrace();
            }
        }

        System.out.println("Scann completed");
        fw.close();
        b.close();
    }

    public static void checkURL(String strURL, boolean validateChain) throws Exception {
        X509Certificate xer = null;
        String dn = null;
        String urlOnly = null;
        String token = null;
        InetAddress addr =null;
        Certificate[] certs;
        System.out.println("Validating cert for:" + strURL + "..on ports:" + ports);
        if (!strURL.toLowerCase().startsWith("https://")) {
            strURL = "https://" + strURL;
        }
        StringTokenizer st = new StringTokenizer(ports, ",");
        while (st.hasMoreTokens()) {
            try {
                token = st.nextToken();
                //strURL = strURL + ":" + st.nextToken();
                URL destinationURL = new URL(strURL + ":" + token);
                HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
                conn.setConnectTimeout(2000);
                conn.connect();
                for (Certificate cert : certs = conn.getServerCertificates()) {
                    if (!(cert instanceof X509Certificate)) {
                        continue;
                    }

                    xer = (X509Certificate) cert;
                    dn = xer.getSubjectDN().getName();
                    urlOnly = dn.substring(0, dn.indexOf(","));

                    xer.checkValidity(d);
                    dn = xer.getSubjectDN().getName();
                    urlOnly = dn.substring(0, dn.indexOf(","));
                    
                    addr = InetAddress.getByName(new URL(strURL).getHost());
                    fw.write("PASS," +addr.getHostName() +"," + strURL +":"+token +  "," + urlOnly + "," + sdf.format(xer.getNotAfter()) + System.getProperty("line.separator"));
                    fw.flush();
                    break;
                }
            
        }catch (CertificateExpiredException cee) {
            dn = xer.getSubjectDN().getName();
            urlOnly = dn.substring(0, dn.indexOf(","));
            addr = InetAddress.getByName(new URL(strURL).getHost());
            fw.write("FAIL," + addr.getHostName()+"," + strURL +":"+ token + "," + urlOnly + "," + sdf.format(xer.getNotAfter()) + System.getProperty("line.separator"));
            fw.flush();
//        } finally {
//            if (!validateChain) {
//                break;
//            }

        }catch (Exception e) {
            fw1.write("Error checking URL:" + strURL + ":"+token + "," + e.getMessage() + System.getProperty("line.separator"));
            fw1.flush();
        }
    }

}

static {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {

            @Override
        public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
    }

}
