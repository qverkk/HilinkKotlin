package com.qverkk

import com.fasterxml.jackson.databind.exc.ValueInstantiationException
import com.fasterxml.jackson.dataformat.xml.XmlMapper
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlText
import okhttp3.JavaNetCookieJar
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.logging.HttpLoggingInterceptor
import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.digest.DigestUtils
import java.net.CookieManager
import java.net.CookiePolicy

lateinit var client: OkHttpClient
var sessToken: SessionToken? = null

fun main(args: Array<String>) {
    var token = ""
    val errorsString = "100002 - brak wsparcia w firmware lub błędny adres API\n" +
            "100003 - brak uprawnień\n" +
            "100004 - system zajęty\n" +
            "100005 - brak informacji o danym błędzie\n" +
            "100006 - błędny parametr\n" +
            "100009 - błąd zapisu\n" +
            "103002 - brak informacji o danym błędzie\n" +
            "103015 - brak informacji o danym błędzie\n" +
            "108001 - niepoprawna nazwa użytkownika\n" +
            "108002 - niepoprawne hasło użytkownika\n" +
            "108003 - użytkownik aktualnie zalogowany\n" +
            "108006 - nieprawidłowa nazwa użytkownika lub hasło\n" +
            "108007 - nieprawidłowa nazwa użytkownika lub hasło, osiągnięto limit prób\n" +
            "110024 - bateria poniżej 50% (przy aktualizacji oprogramowania)\n" +
            "111019 - brak odpowiedzi sieci\n" +
            "111020 - przekroczenie czasu sieci\n" +
            "111022 - sieć nie obsługuje\n" +
            "113018 - system zajęty (dotyczy operacji na SMS'ach)\n" +
            "114001 - plik już istnieje\n" +
            "114002 - plik już istnieje\n" +
            "114003 - karta SD jest obecnie w użyciu\n" +
            "114004 - udostępniona ścieżka nie istnieje\n" +
            "114005 - zbyt długa ścieżka dostępu\n" +
            "114006 - brak uprawnień do pliku/katalogu\n" +
            "115001 - brak informacji o danym błędzie\n" +
            "117001 - niepoprawne hasło (przy połączeniu WiFi)\n" +
            "117004 - niepoprawne hasło WISPr (przy połączeniu WiFi)\n" +
            "120001 - połączenie głosowe zajęte\n" +
            "125001 - niepoprawny token\n" +
            "125003 - ERROR_WRONG_SESSION_TOKEN"

    val errors = errorsString.split("\n")

    val logging = HttpLoggingInterceptor()
    logging.setLevel(HttpLoggingInterceptor.Level.HEADERS)

    val cookieManager = CookieManager()

    cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL)

    client = OkHttpClient.Builder().cookieJar(JavaNetCookieJar(cookieManager)).addInterceptor {
        val orginal = it.request()

        if (sessToken != null) {
            val authorized = orginal.newBuilder()
                .addHeader("Cookie", "SessionID=${sessToken!!.sesInfo}")
                .addHeader("__RequestVerificationToken", sessToken!!.tokInfo)
                .build()

            it.proceed(authorized)
        } else {
            it.proceed(orginal)
        }
    }.addInterceptor(logging).build()


    val xmlMapper = XmlMapper()
    sessToken = getSessionToken()
    val loginUser = Login(
        "admin",
        Base64.encodeBase64String(
            DigestUtils.sha256Hex(
                "admin" +
                        Base64.encodeBase64String(DigestUtils.sha256("password")) +
                        sessToken!!.tokInfo
            ).toByteArray()
        )
    )

    val loginRequestBody = (xmlMapper.writeValueAsString(loginUser))
    println(loginRequestBody)

    val requestBody = RequestBody.create("application/xml".toMediaTypeOrNull(), loginRequestBody)
    val request = Request.Builder().url("http://192.168.8.1/api/user/login").post(
        requestBody
    ).build()

    val response = client.newCall(request).execute()

    val bodyResponse = response.body?.string()
    println("Response: $bodyResponse")

    try {
        val errorResponse = xmlMapper.readValue(bodyResponse, Error::class.java)
        errors.forEach {
            if (it.contains(errorResponse.code.toString())) {
                println(it)
                return@forEach
            }
        }
    } catch (ex: ValueInstantiationException) {
        val connectionResponse = xmlMapper.readValue(bodyResponse, Response::class.java)
        println(connectionResponse.status)
    }

    val tokenReques = Request.Builder().url("http://192.168.8.1/api/webserver/token").get().build()
    val tokenResponse = client.newCall(tokenReques).execute()

    val tokenBodyResponse = tokenResponse.body?.string()
    val tokenResponseObj = xmlMapper.readValue(tokenBodyResponse, TokenResponse::class.java)
//    token = tokenResponseObj.token

    val statsRequest = Request.Builder().url("http://192.168.8.1/api/net/net-mode").get().build()
    val statsResponse = client.newCall(statsRequest).execute()

    statsResponse.request.headers.forEach { println(it.first + " " + it.second) }

    val statsBodyResponse = statsResponse.body?.string()
    println("Response $statsBodyResponse")
}

@JacksonXmlRootElement(localName = "response")
data class TokenResponse(
    @JacksonXmlProperty(localName = "token")
    val token: String
)

data class Response(
    @JacksonXmlText
    @JacksonXmlProperty(localName = "response")
    val status: String?
)

@JacksonXmlRootElement(localName = "request")
data class Login(
    val username: String,
    val password: String,
    @JacksonXmlProperty(localName = "password_type")
    val password_type: Int = 4
)

@JacksonXmlRootElement(localName = "error")
data class Error(
    @JacksonXmlProperty(localName = "code")
    val code: Int,
    @JacksonXmlProperty(localName = "message")
    val message: String
)

@JacksonXmlRootElement(localName = "response")
data class Token(
    @JacksonXmlProperty(localName = "token")
    val token: String
)

@JacksonXmlRootElement(localName = "response")
data class SessionToken(
    @JacksonXmlProperty(localName = "SesInfo")
    val sesInfo: String,
    @JacksonXmlProperty(localName = "TokInfo")
    val tokInfo: String
)

fun getToken(): String {
    val url = "http://192.168.8.1/api/webserver/token"
    val request = Request.Builder().url(url).get().build()

    val response = client.newCall(request).execute()
    val xmlMapper = XmlMapper()
    val responseString = response.body?.string()
    val token = xmlMapper.readValue(responseString, Token::class.java)
    return token.token
}

fun getSessionToken(): SessionToken {
    val url = "http://192.168.8.1/api/webserver/SesTokInfo"
    val request = Request.Builder().url(url).get().build()

    val response = client.newCall(request).execute()
    val xmlMapper = XmlMapper()
    val responseString = response.body?.string()
    return xmlMapper.readValue(responseString, SessionToken::class.java)
}
