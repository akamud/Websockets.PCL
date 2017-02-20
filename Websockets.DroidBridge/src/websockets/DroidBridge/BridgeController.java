
/**
 * Created by Nicholas Ventimiglia on 11/27/2015.
 * nick@avariceonline.com
 * <p/>
 * Android Websocket bridge application. Beacause Mono Networking sucks.
 * Unity talks with BridgeClient (java) and uses a C Bridge to raise events.
 * .NET Methods <-->  BridgeClient (Java / NDK) <--->  Websocket (Java)
 */
package websockets.DroidBridge;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

//https://github.com/koush/AndroidAsync
import com.koushikdutta.async.AsyncServer;
import com.koushikdutta.async.callback.CompletedCallback;
import com.koushikdutta.async.http.AsyncHttpClient;
import com.koushikdutta.async.http.AsyncHttpGet;
import com.koushikdutta.async.http.AsyncHttpRequest;
import com.koushikdutta.async.http.WebSocket;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Map;


public class BridgeController {

    private WebSocket mConnection;
    private static String TAG = "websockets";
    private KeyStore appKeyStore;
    private X509TrustManager defaultTrustManager;

    //MUST BE SET
    public BridgeProxy proxy;
    Handler mainHandler;


    public BridgeController() {
        Log.d(TAG, "ctor");
        mainHandler   = new Handler(Looper.getMainLooper());
    }

    // connect websocket
    public void Open(final String wsuri, final String protocol, final Map<String, String> headers) throws NoSuchAlgorithmException, KeyStoreException {
        Log("BridgeController:Open");

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init((KeyStore) null);

        X509TrustManager x509TrustManager = null;
        for (TrustManager t : tmf.getTrustManagers()) {
            if (t instanceof X509TrustManager) {
                x509TrustManager = (X509TrustManager)t;
            }
        }

        appKeyStore = loadAppKeyStore();
        final X509TrustManager finalX509TrustManager = x509TrustManager;

        AsyncHttpClient.getDefaultInstance().getSSLSocketMiddleware().setTrustManagers(new TrustManager[] { new X509TrustManager() {
            private boolean isCertKnown(X509Certificate cert) {
                try {
                    return appKeyStore.getCertificateAlias(cert) != null;
                } catch (KeyStoreException e) {
                    return false;
                }
            }

            private boolean isExpiredException(Throwable e) {
                do {
                    if (e instanceof CertificateExpiredException)
                        return true;
                    e = e.getCause();
                } while (e != null);
                return false;
            }

            public void checkCertTrusted(X509Certificate[] chain, String authType, boolean isServer)
                                throws CertificateException
            {
                try {
                    if (isServer)
                        finalX509TrustManager.checkServerTrusted(chain, authType);
                    else
                        finalX509TrustManager.checkClientTrusted(chain, authType);
                } catch (CertificateException ae) {
                    // if the cert is stored in our appTrustManager, we ignore expiredness
                    if (isExpiredException(ae)) {
                        return;
                    }
                    if (isCertKnown(chain[0])) {
                        return;
                    }
                    try {
                        if (defaultTrustManager == null)
                            throw ae;
                        if (isServer)
                            defaultTrustManager.checkServerTrusted(chain, authType);
                        else
                            defaultTrustManager.checkClientTrusted(chain, authType);
                    } catch (CertificateException e) {
                        e.printStackTrace();
                        throw e;
                    }
                }
            }

            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return finalX509TrustManager.getAcceptedIssuers();
            }

            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) throws CertificateException {
                checkCertTrusted(certs, authType, false);
            }

            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) throws CertificateException {
                checkCertTrusted(certs, authType, true);
            }
        }});

        SSLContext sslContext = null;

        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);

            AsyncHttpClient.getDefaultInstance().getSSLSocketMiddleware().setSSLContext(sslContext);
        } catch (Exception e){
            Log.d("SSLCONFIG", e.toString(), e);
        }

        AsyncHttpGet get = new AsyncHttpGet(wsuri.replace("ws://", "http://").replace("wss://", "https://"));
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            get.addHeader(entry.getKey(), entry.getValue());
        }
        AsyncHttpClient.getDefaultInstance().websocket((AsyncHttpRequest)get, protocol, new AsyncHttpClient
                .WebSocketConnectCallback() {
            @Override
            public void onCompleted(Exception ex, WebSocket webSocket) {
                if (ex != null) {
                    Error(ex.toString());
                    return;
                }

                mConnection = webSocket;
                RaiseOpened();

                webSocket.setClosedCallback(new CompletedCallback() {
                    @Override
                    public void onCompleted(Exception e) {
                        mConnection = null;
                        RaiseClosed();
                    }
                });


                webSocket.setStringCallback(new WebSocket.StringCallback() {
                    public void onStringAvailable(final String s) {
                        RaiseMessage(s);
                    }
                });
            }
        });
    }

    public void Close() {

        try
        {
            if(mConnection == null)
                return;
            mConnection.close();

        }catch (Exception ex){
            RaiseError("Error Close - "+ex.getMessage());
        }
    }

    // send a message
    public void Send(final String message) {
        try
        {
            if(mConnection == null)
                return;
            mConnection.send(message);
        }catch (Exception ex){
            RaiseError("Error Send - "+ex.getMessage());
        }
    }

    private void Log(final String args) {
        Log.d(TAG, args);

        RaiseLog(args);
    }

    private void Error(final String args) {
        Log.e(TAG, args);

        RaiseError(String.format("Error: %s", args));
    }

    private void RaiseOpened() {
      try{
          if(proxy != null)
              proxy.RaiseOpened();
      }catch(Exception ex){
          RaiseClosed();
          Error("Failed to Open");
      }
    }

    private void RaiseClosed() {
        try{
            if(proxy != null)
                proxy.RaiseClosed();
        }catch(Exception ex){
            RaiseClosed();
            Error("Failed to Close");
        }
    }

    private void RaiseMessage(String message) {
        try{
            if(proxy != null)
                proxy.RaiseMessage(message);
        }catch(Exception ex){
            RaiseClosed();
            Error("Failed to Raise");
        }
    }

    private void RaiseLog(String message) {
        try{
            if(proxy != null)
                proxy.RaiseLog(message);
        }catch(Exception ex){
            RaiseClosed();
            Error("Failed to Log");
        }
    }

    private void RaiseError(String message) {
        try{
            if(proxy != null)
                proxy.RaiseError(message);
        }catch(Exception ex){
            RaiseClosed();
            Error("Failed to Error");
        }
    }

    public static KeyStore loadAppKeyStore() {
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            return null;
        }
        try {
            ks.load(null, null);
            //ks.load(new java.io.FileInputStream(keyStoreFile), "MTM".toCharArray());
        } catch (java.io.FileNotFoundException e) {
        } catch (Exception e) {
        }
        return ks;
    }
}
