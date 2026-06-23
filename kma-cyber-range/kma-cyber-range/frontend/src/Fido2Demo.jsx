import React, { useState } from "react";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";

const API_BASE = `http://${window.location.hostname}:8080`; 

export default function Fido2Demo() {
  const [username, setUsername] = useState("employee01");
  const [password, setPassword] = useState("employee123");
  const [token, setToken] = useState("");
  const [result, setResult] = useState("");

  const show = (obj) => {
    setResult(JSON.stringify(obj, null, 2));
  };

  const passwordLogin = async () => {
    try {
      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await resp.json();

      if (!resp.ok) {
        show(data);
        return;
      }

      setToken(data.access_token);
      show(data);
    } catch (err) {
      show({
        error: "Password login failed",
        message: String(err),
      });
    }
  };

  const registerPasskey = async () => {
    if (!token) {
      alert("Cần login bằng password trước để đăng ký passkey cho tài khoản.");
      return;
    }

    try {
      const optionsResp = await fetch(`${API_BASE}/auth/fido2/register/start`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const optionsJSON = await optionsResp.json();

      if (!optionsResp.ok) {
        show(optionsJSON);
        return;
      }

      const attResp = await startRegistration({ optionsJSON });

      const verifyResp = await fetch(`${API_BASE}/auth/fido2/register/finish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ credential: attResp }),
      });

      const verifyJSON = await verifyResp.json();
      show(verifyJSON);
    } catch (err) {
      show({
        error: "Register passkey failed",
        message: String(err),
      });
    }
  };

  const loginWithPasskey = async () => {
    try {
      const optionsResp = await fetch(`${API_BASE}/auth/fido2/login/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username }),
      });

      const optionsJSON = await optionsResp.json();

      if (!optionsResp.ok) {
        show(optionsJSON);
        return;
      }

      const asseResp = await startAuthentication({ optionsJSON });

      const verifyResp = await fetch(`${API_BASE}/auth/fido2/login/finish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ credential: asseResp }),
      });

      const verifyJSON = await verifyResp.json();

      if (verifyJSON.access_token) {
        setToken(verifyJSON.access_token);
      }

      show(verifyJSON);
    } catch (err) {
      show({
        error: "Login with passkey failed",
        message: String(err),
      });
    }
  };

  const validateToken = async () => {
    if (!token) {
      alert("Chưa có JWT token.");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/auth/session/validate`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await resp.json();
      show(data);
    } catch (err) {
      show({
        error: "Validate token failed",
        message: String(err),
      });
    }
  };

  return (
    <div style={{ padding: 24, fontFamily: "Arial, sans-serif" }}>
      <h1>KMA FIDO2 / WebAuthn Demo</h1>

      <p>
        Demo này dùng React để gọi WebAuthn API của trình duyệt. Khi đăng ký hoặc đăng nhập passkey,
        Chrome/Edge sẽ gọi Windows Hello để xác thực bằng vân tay, PIN hoặc cơ chế xác thực có sẵn trên máy.
      </p>

      <div style={{ marginBottom: 12 }}>
        <label>Username: </label>
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{ marginRight: 12, padding: 6 }}
        />

        <label>Password: </label>
        <input
          value={password}
          type="password"
          onChange={(e) => setPassword(e.target.value)}
          style={{ padding: 6 }}
        />
      </div>

      <div style={{ marginBottom: 16 }}>
        <button onClick={passwordLogin}>
          1. Password Login
        </button>

        <button onClick={registerPasskey} style={{ marginLeft: 8 }}>
          2. Register Passkey / Windows Hello
        </button>

        <button onClick={loginWithPasskey} style={{ marginLeft: 8 }}>
          3. Login with Passkey
        </button>

        <button onClick={validateToken} style={{ marginLeft: 8 }}>
          4. Validate JWT
        </button>
      </div>

      <h3>Current JWT</h3>
      <textarea
        value={token}
        readOnly
        rows={5}
        style={{ width: "100%", fontFamily: "monospace" }}
      />

      <h3>Result</h3>
      <pre
        style={{
          background: "#111",
          color: "#0f0",
          padding: 12,
          minHeight: 200,
          whiteSpace: "pre-wrap",
          overflowX: "auto",
        }}
      >
        {result}
      </pre>
    </div>
  );
}
