package com.friddle.androidtest;

import android.os.Bundle;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.RadioButton;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    static {
        System.loadLibrary("androidtest");
    }

    private EditText inputText;
    private Button processBtn;
    private RadioGroup modeGroup;
    private CheckBox falsePositiveCheckBox;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        inputText = findViewById(R.id.inputText);
        processBtn = findViewById(R.id.processBtn);
        modeGroup = findViewById(R.id.modeGroup);
        falsePositiveCheckBox = findViewById(R.id.falsePositiveCheckBox);

        processBtn.setOnClickListener(v -> {
            String data = inputText.getText().toString();
            int selectedId = modeGroup.getCheckedRadioButtonId();
            int mode = 0;
            if (selectedId == R.id.rbStringcopy) {
                mode = 1;
            } else if (selectedId == R.id.rbBase64) {
                mode = 2;
            } else if (selectedId == R.id.rbAES) {
                mode = 3;
            } else if (selectedId == R.id.rbAESLib) {
                mode = 4;
            } else {
                Toast.makeText(this, "Please select a mode", Toast.LENGTH_SHORT).show();
                return;
            }
            boolean fpMode = falsePositiveCheckBox.isChecked();
            String result = nativeProcess(data, mode, fpMode);
            Toast.makeText(this, result, Toast.LENGTH_LONG).show();
        });
    }

    private native String nativeProcess(String input, int mode, boolean falsePositiveMode);
}