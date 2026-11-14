package com.liskovsoft.sharedutils.helpers

import info.guardianproject.netcipher.NetCipher
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object NetworkHelpers {
    @JvmStatic
    fun getHttpsURLConnection(url: URL): HttpURLConnection {
        // Original value
        //val conn = url.openConnection() as HttpURLConnection
        val conn = getBestHttpsURLConnection(url)

        // Imitate 'keepAlive' = false (cause buffering?)
        // https://stackoverflow.com/questions/3352424/httpurlconnection-openconnection-fails-second-time/3943820#3943820
        //conn.setRequestProperty("connection", "close")

        return conn
    }

    /**
     * Doesn't work with ip (HTTP/1.1 400 Bad Request)
     *
     * Server rejects connection by ip
     */
    @JvmStatic
    fun getDohURLConnection(url: URL): HttpURLConnection {
        // Keep the original hostname so Android performs normal certificate
        // and hostname verification. The previous IP substitution bypassed it.
        return getBestHttpsURLConnection(url)
    }

    private fun getBestHttpsURLConnection(url: URL): HttpsURLConnection = NetCipher.getCompatibleHttpsURLConnection(url)
}
