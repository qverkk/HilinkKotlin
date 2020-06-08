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

// ==============================================================================
// EXCEPTIONS
// ==============================================================================

class ConnectionErrorException(message: String): Exception(message)

open class ResponseErrorException(message:String, public val code: Int): Exception(message)

class ResponseErrorSystemBusyException(message:String, code: Int): ResponseErrorException(message, code)
class ResponseErrorLoginRequiredException(message:String, code: Int): ResponseErrorException(message, code)
class ResponseErrorNotSupportedException(message:String, code: Int): ResponseErrorException(message, code)
class ResponseErrorLoginCsrfException(message:String, code: Int): ResponseErrorException(message, code)

class LoginErrorUsernameWrongException(message:String, code: Int): ResponseErrorException(message, code)
class LoginErrorPasswordWrongException(message:String, code: Int): ResponseErrorException(message, code)
class LoginErrorAlreadyLoginException(message:String, code: Int): ResponseErrorException(message, code)
class LoginErrorUsernamePasswordWrongException(message:String, code: Int): ResponseErrorException(message, code)
class LoginErrorUsernamePasswordOverrunException(message:String, code: Int): ResponseErrorException(message, code)
class LoginErrorUsernamePasswordModifyException(message:String, code: Int): ResponseErrorException(message, code)

// ==============================================================================
// ENUMS
// ==============================================================================

enum class ResponseCodeEnum(val value: Int) {
    ERROR_SYSTEM_UNKNOWN(100001),
    ERROR_SYSTEM_NO_SUPPORT(100002),
    ERROR_SYSTEM_NO_RIGHTS(100003),
    ERROR_SYSTEM_BUSY(100004),
    ERROR_SYSTEM_CSRF(125002);


    companion object {
        private val map = ResponseCodeEnum.values().associateBy(ResponseCodeEnum::value)
        fun fromInt(type: Int) = map[type]
    }
}

enum class PasswordTypeEnum(val value: Int) {
    BASE_64(0),
    BASE_64_AFTER_PASSWORD_CHANGE(3),
    SHA256(4);

    companion object {
        private val map = PasswordTypeEnum.values().associateBy(PasswordTypeEnum::value)
        fun fromInt(type: Int) = map[type]
    }
}

enum class LoginErrorEnum(val value: Int) {
    USERNAME_WRONG(108001),
    PASSWORD_WRONG(108002),
    ALREADY_LOGIN(108003),
    USERNAME_PWD_WRONG(108006),
    USERNAME_PWD_ORERRUN(108007),
    USERNAME_PWD_MODIFY(115002);

    companion object {
        private val map = LoginErrorEnum.values().associateBy(LoginErrorEnum::value)
        fun fromInt(type: Int) = map[type]
    }
}

// ==============================================================================
// DATA MODELS
// ==============================================================================

data class Response(
    @JacksonXmlText
    @JacksonXmlProperty(localName = "response")
    val status: String?
)

@JacksonXmlRootElement(localName = "request")
data class StateLogin(
    @JacksonXmlProperty(localName = "State")
    val state: String,
    @JacksonXmlProperty(localName = "Username")
    val username: String,
    @JacksonXmlProperty(localName = "password_type")
    val passwordType: Int = 4
)

@JacksonXmlRootElement(localName = "request")
data class Login(
    @JacksonXmlProperty(localName = "Username")
    val username: String,
    @JacksonXmlProperty(localName = "Password")
    val password: String,
    @JacksonXmlProperty(localName = "password_type")
    val passwordType: Int = 4
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

@JacksonXmlRootElement(localName = "response")
data class NetModeResponse(
    @JacksonXmlProperty(localName = "NetworkMode")
    val networkMode: String,
    @JacksonXmlProperty(localName = "NetworkBand")
    val networkBand: String,
    @JacksonXmlProperty(localName = "LTEBand")
    val lTEBand: String
)


// ==============================================================================
// Huawei class
// ==============================================================================

class Huawei(url: String, username: String = "admin", password: String?) {
    private var _url: String
    private var _username: String
    private var _password: String?
    private lateinit var client: OkHttpClient
    private var requestVerificationTokens: ArrayList<String> = ArrayList<String>()

    init {
        if (!url.endsWith("/")) {
            this._url = "$url/"
        } else {
            this._url = url
        }

        this._username = username
        this._password = password

        this.initializeClient()
        this.initializeCsrfTokens()
    }

    private fun initializeClient() {
        val logging = HttpLoggingInterceptor()
        logging.setLevel(HttpLoggingInterceptor.Level.HEADERS)

        val cookieManager = CookieManager()
        cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL)

        this.client = OkHttpClient.Builder().cookieJar(JavaNetCookieJar(cookieManager)).addInterceptor {
            val orginal = it.request()

            if (!this.requestVerificationTokens.isEmpty()) {
                val verificationToken: String
                if (this.requestVerificationTokens.size > 1) {
                    verificationToken = this.requestVerificationTokens.first()
                    this.requestVerificationTokens.removeAt(0)
                } else {
                    verificationToken = this.requestVerificationTokens.first()
                }

                val authorized = orginal.newBuilder()
                    .addHeader("__RequestVerificationToken", verificationToken)
                    .build()

                it.proceed(authorized)
            } else {
                it.proceed(orginal)
            }
        }.addInterceptor(logging).build()
    }

    private fun initializeCsrfTokens() {
        this.requestVerificationTokens.clear()

        val request = Request.Builder().url(this._url).get().build()

        val response = this.client.newCall(request).execute()
        val responseString = response.body?.string()

        if (responseString != null) {
            val matches = Regex("name=\"csrf_token\"\\s+content=\"(\\S+)\"").findAll(responseString)

            if (matches.any()) {
                matches.forEach { f ->
                    this.requestVerificationTokens.add(f.groupValues[1])
                }
                return // No need to continue
            }
        }

        var token: String
        try {
            val data = this.getToken()
            token = data.token
        } catch (e: ResponseErrorNotSupportedException) {
            val data = this.getSessionToken()
            token = data.tokInfo
        }

        this.requestVerificationTokens.add(token)
    }

    private fun doLoginMagic(passwordType: PasswordTypeEnum?) {
        var passwordEncoded = ""
        if (!this._password!!.isEmpty()) {
            passwordEncoded = if (passwordType == PasswordTypeEnum.SHA256) {
                Base64.encodeBase64String(
                    DigestUtils.sha256Hex(
                        this._username +
                                Base64.encodeBase64String(DigestUtils.sha256Hex(this._password).toByteArray()) +
                                this.requestVerificationTokens.first()
                    ).toByteArray()
                )
            } else {
                Base64.encodeBase64String(this._password!!.toByteArray())
            }
        }

        try {
            val userLoginRequest = Login(this._username, passwordEncoded)
            this.doPostRequest("user/login", userLoginRequest, Response::class.java)
        } catch (e: ResponseErrorException) {

            val errorCodeMessage = when(LoginErrorEnum.fromInt(e.code)) {
                LoginErrorEnum.USERNAME_WRONG -> "Username wrong"
                LoginErrorEnum.PASSWORD_WRONG -> "Password wrong"
                LoginErrorEnum.ALREADY_LOGIN -> "Already login"
                LoginErrorEnum.USERNAME_PWD_WRONG -> "Username and Password wrong"
                LoginErrorEnum.USERNAME_PWD_ORERRUN -> "Password overrun"
                LoginErrorEnum.USERNAME_PWD_MODIFY -> "Password modify"
                else -> "Unknown"
            }

            when(LoginErrorEnum.fromInt(e.code)) {
                LoginErrorEnum.USERNAME_WRONG -> throw LoginErrorUsernameWrongException(errorCodeMessage, e.code)
                LoginErrorEnum.PASSWORD_WRONG -> throw LoginErrorPasswordWrongException(errorCodeMessage, e.code)
                LoginErrorEnum.ALREADY_LOGIN -> throw LoginErrorAlreadyLoginException(errorCodeMessage, e.code)
                LoginErrorEnum.USERNAME_PWD_WRONG -> throw LoginErrorUsernamePasswordWrongException(errorCodeMessage, e.code)
                LoginErrorEnum.USERNAME_PWD_ORERRUN -> throw LoginErrorUsernamePasswordOverrunException(errorCodeMessage, e.code)
                LoginErrorEnum.USERNAME_PWD_MODIFY -> throw LoginErrorUsernamePasswordModifyException(errorCodeMessage, e.code)
                else -> throw ResponseErrorException(errorCodeMessage, e.code)
            }
        }
    }

    fun login() {
        // Some models reportedly close the connection if we attempt to access login state too soon after
        // setting up the session etc. In that case, retry a few times. The error is reported to be
        // ConnectionError: ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response')
        val tries = 5
        for (i in 0..tries) {
            try {
                val stateLogin = this.getStateLogin()
                this.doLoginMagic(PasswordTypeEnum.fromInt(stateLogin.passwordType))
                return
            } catch (e: ConnectionErrorException) {
                if (i == tries - 1) {
                    throw e
                }

                val sleepTime = (i + 1)/ 10
                Thread.sleep(sleepTime.toLong())
            } catch (e: ResponseErrorNotSupportedException) {
                // Prevent this exception from bubbling out from here...
            }
        }
    }

    private fun checkResponse(response: okhttp3.Response, mutator: Class<*>): Any? {
        val responseString = response.body?.string()
        println(responseString)
        if (!response.isSuccessful) {
            throw ConnectionErrorException("Connection error: ${response.code}")
        }

        val xmlMapper = XmlMapper()
        try {
            val errorResponse = xmlMapper.readValue(responseString, Error::class.java)

            val errorCodeMessage = when (ResponseCodeEnum.fromInt(errorResponse.code)) {
                ResponseCodeEnum.ERROR_SYSTEM_BUSY -> "System busy"
                ResponseCodeEnum.ERROR_SYSTEM_NO_RIGHTS -> "No rights (needs login)"
                ResponseCodeEnum.ERROR_SYSTEM_NO_SUPPORT -> "No support"
                ResponseCodeEnum.ERROR_SYSTEM_UNKNOWN -> "Unknown"
                ResponseCodeEnum.ERROR_SYSTEM_CSRF -> "Session error"
                else -> "Unknown error"
            }

            when(ResponseCodeEnum.fromInt(errorResponse.code)) {
                ResponseCodeEnum.ERROR_SYSTEM_BUSY -> throw ResponseErrorSystemBusyException(errorCodeMessage, errorResponse.code)
                ResponseCodeEnum.ERROR_SYSTEM_NO_RIGHTS -> throw ResponseErrorLoginRequiredException(errorCodeMessage, errorResponse.code)
                ResponseCodeEnum.ERROR_SYSTEM_NO_SUPPORT -> throw ResponseErrorNotSupportedException(errorCodeMessage, errorResponse.code)
                ResponseCodeEnum.ERROR_SYSTEM_UNKNOWN ->  throw ResponseErrorException(errorCodeMessage, errorResponse.code)
                ResponseCodeEnum.ERROR_SYSTEM_CSRF -> throw ResponseErrorLoginCsrfException(errorCodeMessage, errorResponse.code)
                else -> throw ResponseErrorException(errorCodeMessage, errorResponse.code)
            }
        } catch (ex: ValueInstantiationException) {
            return xmlMapper.readValue(responseString, mutator)
        }
    }

    fun doGetRequest(endpoint: String, mutator: Class<*>): Any? {
        val url = this._url + "api/" + endpoint
        val request = Request.Builder().url(url).get().build()

        val response = this.client.newCall(request).execute()
        return this.checkResponse(response, mutator)
    }

    fun doPostRequest(endpoint: String, data: Any,  mutator: Class<*>): Any? {
        val url = this._url + "api/" + endpoint
        val xmlMapper = XmlMapper()

        // !FIXME !!!!!!!!!!!!!!!!!
        // !FIXME Jackson XML is somehow broken, it ignores localName when using writeValueAsString....
        // !FIXME !!!!!!!!!!!!!!!!!

        val loginRequestBody = xmlMapper.writeValueAsString(data).replace("passwordType", "password_type").replace("username", "Username")
            .replace("password", "Password").replace("Password_type", "password_type")

        println(loginRequestBody)
        val requestBody = RequestBody.create("application/xml".toMediaTypeOrNull(), loginRequestBody)
        val request = Request.Builder().url(url).post(
            requestBody
        ).build()

        val response = this.client.newCall(request).execute()
        return this.checkResponse(response, mutator)
    }

    fun getStateLogin(): StateLogin {
        return this.doGetRequest("user/state-login", StateLogin::class.java) as StateLogin
    }

    fun getToken(): Token {
        return this.doGetRequest("webserver/token", Token::class.java) as Token
    }

    fun getSessionToken(): SessionToken {
        return this.doGetRequest("webserver/SesTokInfo", SessionToken::class.java) as SessionToken
    }

    fun getNetNetMode(): NetModeResponse {
        return this.doGetRequest("net/net-mode", NetModeResponse::class.java) as NetModeResponse
    }
}

// ==============================================================================
// MAIN
// ==============================================================================

fun main(args: Array<String>) {

    val huawei = Huawei("http://192.168.1.8/", "admin", "YOUR_PASSWORD")
    huawei.login()
    println(huawei.getNetNetMode())
}
