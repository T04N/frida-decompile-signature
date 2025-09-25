frida -U -f com.min.car -l \_agent.js

Mở app trước
adb shell monkey -p com.min.car 1

Kiem tra da chay
adb shell ps | grep com.min.car

spawn
frida -U -f com.min.car -l \_agent.js

Chạy watcher để tự rebuild

frida -U -f com.min.car -l frida_simple_input.js
