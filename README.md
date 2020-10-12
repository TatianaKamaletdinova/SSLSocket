# SSLSocket

 val serverAddress: InetAddress = InetAddress.getByName("192.168.0.0")

        val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
        val caInput: InputStream =
            requireContext().resources.openRawResource(
                R.raw.cert
            )
            
        val ca: X509Certificate = caInput.use {
            cf.generateCertificate(it) as X509Certificate
        }
        System.out.println("ca=" + ca.subjectDN)

        // Create a KeyStore containing our trusted CAs
        val keyStoreType = KeyStore.getDefaultType()
        val keyStore = KeyStore.getInstance(keyStoreType).apply {
            load(null, null)
            setCertificateEntry("ca", ca)
        }

        // Create a TrustManager that trusts the CAs inputStream our KeyStore
        val tmfAlgorithm: String = TrustManagerFactory.getDefaultAlgorithm()
        val tmf: TrustManagerFactory = TrustManagerFactory.getInstance(
            tmfAlgorithm
        ).apply {
            init(keyStore)
        }

        // Create an SSLContext that uses our TrustManager
        val context: SSLContext = SSLContext.getInstance("TLSv1").apply {
            init(null, tmf.trustManagers, SecureRandom())
        }

        val factory = TLSSocketFactory(tmf)
        sslSocket = factory.createSocket(serverAddress, 9001) as SSLSocket
        sslSocket.useClientMode = true

        try{
            sslSocket.startHandshake()
        }catch (ex: java.lang.Exception){
            val error = ex
        }finally {
            sslSocket.close()
        }
        
        
 ERROR:
 javax.net.ssl.SSLProtocolException: SSL handshake aborted: ssl=0x70c62dd6d8: Failure in SSL library, usually a protocol error
error:10000410:SSL routines:OPENSSL_internal:SSLV3_ALERT_HANDSHAKE_FAILURE (third_party/openssl/boringssl/src/ssl/tls_record.cc:594 0x70e62e3ff8:0x00000001)
