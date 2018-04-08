package io.zenandroid.fingerprintauth.app;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import io.zenandroid.fingerprintauth.R;
import io.zenandroid.fingerprintauth.lib.FingerprintAuth;

/**
 * Created by alex on 08/04/2018.
 */

public class LoginActivity extends AppCompatActivity {

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        FingerprintAuth.INSTANCE.setDisabledByKillSwitch(false);
        FingerprintAuth.INSTANCE.setWhitelistEnabled(false);
        FingerprintAuth.INSTANCE.init(this);
    }

    @Override
    protected void onResume() {
        super.onResume();

        final FingerprintAuth.Status status = FingerprintAuth.INSTANCE.getStatus();

        ((TextView)findViewById(R.id.text)).setText(status.toString());

        final String password = "test password123";

        FingerprintAuth.INSTANCE.savePassword(getFragmentManager(), password, new FingerprintAuth.Callback<Object>() {
            @Override
            public void onSuccess(Object result) {
                Toast.makeText(LoginActivity.this, "Saved password: "+password, Toast.LENGTH_LONG).show();
                FingerprintAuth.INSTANCE.getSavedPassword(getFragmentManager(), new FingerprintAuth.Callback<String>() {

                    @Override
                    public void onError() {
                        Toast.makeText(LoginActivity.this, "Password decrypt failed", Toast.LENGTH_LONG).show();
                    }

                    @Override
                    public void onSuccess(String result) {
                        Toast.makeText(LoginActivity.this, "Password decrypted: "+ result, Toast.LENGTH_LONG).show();
                    }
                });
            }

            @Override
            public void onError() {
                Toast.makeText(LoginActivity.this, "Password save failed", Toast.LENGTH_LONG).show();
            }
        });
    }
}
