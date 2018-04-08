package io.zenandroid.fingerprintauth.lib

import android.annotation.SuppressLint
import android.app.FragmentManager
import android.app.KeyguardManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import android.util.Base64
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


/**
 * Created by alex on 08/04/2018.
 */
@SuppressLint("StaticFieldLeak")
object FingerprintAuth {
    private const val SHARED_PREFS_NAME = "FingerprintAuth"
    private const val ENCRYPTED_PASSWORD_KEY = "ENCRYPTED_PASSWORD_KEY"
    private const val KEY_NAME = "KEY_NAME"

    enum class Status {
        NOT_INITIALIZED,
        NOT_SUPPORTED,
        NO_FINGERPRINT_REGISTERED,
        NO_LOCK_SCREEN,
        FINGERPRINT_CHANGED,
        NO_SAVED_PASSWORD,
        AVAILABLE
    }

    var disabledByKillSwitch = false
    var whitelistEnabled = false
    var whitelist: List<String>? = null

    private lateinit var context: Context
    private lateinit var fingerprintManager: FingerprintManagerCompat
    private lateinit var prefs: SharedPreferences
    private lateinit var keyguardManager: KeyguardManager
    private lateinit var cipher: Cipher
    private lateinit var keyStore: KeyStore
    private lateinit var keyGenerator: KeyGenerator

    private var inited = false

    @SuppressLint("NewApi")
    fun getStatus(): Status = when {
        !inited ->
            Status.NOT_INITIALIZED
        disabledByKillSwitch || Build.VERSION.SDK_INT < Build.VERSION_CODES.M || !fingerprintManager.isHardwareDetected ->
            Status.NOT_SUPPORTED
        !fingerprintManager.hasEnrolledFingerprints() ->
            Status.NO_FINGERPRINT_REGISTERED
        !keyguardManager.isDeviceSecure ->
            Status.NO_LOCK_SCREEN
        !initCipher(cipher, KEY_NAME) ->
            Status.FINGERPRINT_CHANGED
        !prefs.contains(ENCRYPTED_PASSWORD_KEY) ->
            Status.NO_SAVED_PASSWORD
        else ->
            Status.AVAILABLE
    }

    fun init(context: Context) {
        this.context = context.applicationContext
        this.fingerprintManager = FingerprintManagerCompat.from(this.context)
        this.prefs = this.context.getSharedPreferences(SHARED_PREFS_NAME, Context.MODE_PRIVATE)
        this.keyguardManager = this.context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to get an instance of KeyStore", e)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7)
            try {
                keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException("Failed to get an instance of KeyGenerator", e)
            } catch (e: NoSuchProviderException) {
                throw RuntimeException("Failed to get an instance of KeyGenerator", e)
            }
            createKey(KEY_NAME, true)
        }

        inited = true
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun initCipher(cipher: Cipher, keyName: String): Boolean {
        try {
            keyStore.load(null)
            val key = keyStore.getKey(keyName, null) as SecretKey
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return true
        } catch (e: KeyPermanentlyInvalidatedException) {
            return false
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: IOException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        }
    }



    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     *
     * @param keyName the name of the key to be created
     * @param invalidatedByBiometricEnrollment if `false` is passed, the created key will not
     * be invalidated even if a new fingerprint is enrolled.
     * The default value is `true`, so passing
     * `true` doesn't change the behavior
     * (the key will be invalidated if a new fingerprint is
     * enrolled.). Note that this parameter is only valid if
     * the app works on Android N developer preview.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun createKey(keyName: String, invalidatedByBiometricEnrollment: Boolean) {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            keyStore.load(null)
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder

            val builder = KeyGenParameterSpec.Builder(keyName,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    // Require the user to authenticate with a fingerprint to authorize every use
                    // of the key
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)

            // This is a workaround to avoid crashes on devices whose API level is < 24
            // because KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment is only
            // visible on API level +24.
            // Ideally there should be a compat library for KeyGenParameterSpec.Builder but
            // which isn't available yet.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
            }
            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        } catch (e: CertificateException) {
            throw RuntimeException(e)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }


    @RequiresApi(Build.VERSION_CODES.M)
    fun savePassword(fragmentManager: FragmentManager, password : String, callback: Callback<Any>) {
        val dialog = FingerprintDialog()
        val cancellationSignal = CancellationSignal()
        dialog.show(fragmentManager, "FINGERPRINT_DIALOG")
        initCipher(cipher, KEY_NAME)
        fingerprintManager.authenticate(
                FingerprintManagerCompat.CryptoObject(cipher),
                0,
                cancellationSignal,
                object: FingerprintManagerCompat.AuthenticationCallback() {
                    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence) {
                        callback.onError()
                    }

                    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence) {
                    }

                    override fun onAuthenticationFailed() {
                    }

                    @RequiresApi(Build.VERSION_CODES.M)
                    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                        dialog.dismiss()
                        val encrypted = cipher.doFinal(password.toByteArray())
                        prefs.edit()
                                .putString(ENCRYPTED_PASSWORD_KEY, Base64.encodeToString(encrypted, Base64.DEFAULT))
                                .apply()
                        callback.onSuccess(Any())
                    }
                },
                null
        )
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun getSavedPassword(fragmentManager: FragmentManager, callback: Callback<String>) {
        val dialog = FingerprintDialog()
        val cancellationSignal = CancellationSignal()
        dialog.show(fragmentManager, "FINGERPRINT_DIALOG")
        initCipher(cipher, KEY_NAME)
        fingerprintManager.authenticate(
                FingerprintManagerCompat.CryptoObject(cipher),
                0,
                cancellationSignal,
                object: FingerprintManagerCompat.AuthenticationCallback() {
                    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence) {
                        callback.onError()
                    }

                    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence) {
                    }

                    override fun onAuthenticationFailed() {
                    }

                    @RequiresApi(Build.VERSION_CODES.M)
                    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                        dialog.dismiss()
                        val encrypted = Base64.decode(prefs.getString(ENCRYPTED_PASSWORD_KEY, ""), Base64.DEFAULT)
                        val password = String(cipher.doFinal(encrypted))
                        callback.onSuccess(password)
                    }
                },
                null
        )
    }

    interface Callback<in T> {
        fun onSuccess(result: T)
        fun onError()
    }
}