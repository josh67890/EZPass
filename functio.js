window.onload = function() {
    document.getElementById('generate').addEventListener('click', generatePassword);
    document.getElementById('show-password').addEventListener('click', showpassword);
  }
  
  document.addEventListener('DOMContentLoaded', function() {
    const url = new URL(window.location.href);
    const hostname = url.hostname.replace(/^www\./, '');
    document.getElementById('servername').value = hostname;
  
    document.getElementById('2fa').disabled = true;
    document.getElementById("send_button").disabled = true;
  });
  
  async function showpassword() {
    const passfield = document.getElementById("privkey");
    const show = document.getElementById("show-password").checked;
    passfield.type = show ? "text" : "password";
  }
  
  async function generatePassword() {
    const serverName = document.getElementById('servername').value;
    const privateKey = document.getElementById('privkey').value;
    const email = document.getElementById('email').value;
  
    if (!serverName || !privateKey || !email) {
      alert('Please supply server name, key, and email address.');
      return;
    }
  
    let sequence = "1234567890-=!@#$%^&*()_+qwertyuiop[]\\QWERTYUIOP{}|asdfghjkl;'ASDFGHJKL:\"zxcvbnm,./ZXCVBNM<>?";
    const alphanum = document.getElementById('alphanum');
    if (alphanum.checked) {
      sequence = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
    }
  
    let password_length = 12;
    const xtra_length = document.getElementById('longpassword');
    if (xtra_length.checked) {
      password_length = 16;
    }
  
    const otp = document.getElementById('2fa-check');
    const use2fa = otp.checked;
    if (use2fa) {
      document.getElementById('2fa').disabled = false;
      document.getElementById('send_button').disabled = false;
    }
  
    const servernameBytes = new TextEncoder().encode(serverName);
    const privkeyBytes = new TextEncoder().encode(privateKey);
    const emailBytes = new TextEncoder().encode(email);
  
    const hashedBytes = new Uint8Array(await crypto.subtle.digest('SHA-384', concatBytes(privkeyBytes, servernameBytes, emailBytes, privkeyBytes)));
    const hex_hash = bytesToHex(hashedBytes);
  
    try {
      const response = await fetch('https://realproject-ysnfbl3z5a-zf.a.run.app/process', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store'
        },
        body: JSON.stringify({
          message: hex_hash,
          email: email,
          otp: use2fa
        })
      });
  
      if (!response.ok) {
        throw new Error('Network response was not ok: ' + response.statusText);
      }
  
      const data = await response.json();
      if (data.hex_bytes === "too many requests in 10 seconds" || data.hex_bytes === "exceeded limit of allowed requests a day (currently 300)") {
        alert(data.hex_bytes);
        return;
      }
      const response_bytes = hexToBytes(data.hex_bytes);
  
      if (use2fa) {
        document.getElementById("send_button").addEventListener("click", async function send2fa() {
          await handle2fa(response_bytes, privkeyBytes, sequence, password_length);
        });
      } else {
        await handleNo2fa(response_bytes, privkeyBytes, sequence, password_length);
      }
    } catch (error) {
      console.error('Error:', error);
    }
  }
  
  async function handle2fa(response_bytes, privkeyBytes, sequence, password_length) {
    const otpCode = document.getElementById("2fa").value;
    const otpCodeBytes = new TextEncoder().encode(otpCode);
    const hashedOtp = new Uint8Array(await crypto.subtle.digest('SHA-384', concatBytes(privkeyBytes, otpCodeBytes)));
    const fullHashed = new Uint8Array(await crypto.subtle.digest('SHA-384', concatBytes(response_bytes, hashedOtp)));
  
    const final_password = Array.from({ length: password_length }, (_, i) => sequence[fullHashed[i] % sequence.length]).join('');
    document.getElementById("password").value = final_password;
  }
  
  async function handleNo2fa(response_bytes, privkeyBytes, sequence, password_length) {
    const fullHashed = new Uint8Array(await crypto.subtle.digest('SHA-384', concatBytes(response_bytes, privkeyBytes)));
    const final_password = Array.from({ length: password_length }, (_, i) => sequence[fullHashed[i] % sequence.length]).join('');
    document.getElementById("password").value = final_password;
  }
  
  function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  
  function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  }
  
  function concatBytes(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    arrays.forEach(arr => {
      result.set(arr, offset);
      offset += arr.length;
    });
    return result;
  }
  
