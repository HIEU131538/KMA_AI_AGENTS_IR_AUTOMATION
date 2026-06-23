import React, { useEffect, useState } from "react";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import "./App.css";

const API_BASE = `http://${window.location.hostname}:8080`;

function App() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [token, setToken] = useState("");
  useEffect(() => {

      console.log("Current token:", token);

  }, [token]);
  
  const [currentUser, setCurrentUser] = useState(null);

  const [employees, setEmployees] = useState([]);
  const [selectedEmployee, setSelectedEmployee] = useState(null);
  const [adminStatus, setAdminStatus] = useState(null);
  const [result, setResult] = useState("");
  
  const [securityEvents, setSecurityEvents] = useState([]);
  const [threatEvents, setThreatEvents] = useState([]);
  const [aiResult, setAiResult] = useState(null);
  const [incidents, setIncidents] = useState([]);

async function loadAiAnalysis() {

    console.log("Calling AI Analysis...");

    try {
  
        console.log("TOKEN =", token);

        console.log(authHeaders());

        const resp = await fetch(
            `${API_BASE}/api/v1/security/analyze`,
            {
                method: "GET",
                headers: authHeaders(),
            }
        );

        const data = await resp.json();

        if (resp.ok) {
            setAiResult(data);
        } else {
            console.error("AI Analysis API Error:", data);
        }

    } catch (err) {

        console.error("AI Analysis Failed:",err);

    }
}

useEffect(() => {

  if (!token) {
    return;
  }

  loadSecurityEvents();
  loadThreatEvents();
  loadAiAnalysis();
  loadIncidents();

  const timer = setInterval(() => {
    loadSecurityEvents();
    loadThreatEvents();
    loadAiAnalysis();
    loadIncidents();
  }, 3000);

  return () => clearInterval(timer);

}, [token]);
  const [profileForm, setProfileForm] = useState({
    full_name: "Nguyen Quang Dat",
    phone: "0999999999",
    email: "employee01@kma.local",
    role: "admin",
  });

  const [exportUrl, setExportUrl] = useState("http://kma-app:8000/health");
  const [cvFile, setCvFile] = useState(null);

  const show = (obj) => {
    setResult(JSON.stringify(obj, null, 2));
  };

  const authHeaders = () => ({
    Authorization: `Bearer ${token}`,
  });

  const jsonHeaders = () => ({
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  });

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
      setCurrentUser(data.user);
      show(data);
    } catch (err) {
      show({
        error: "Password login failed",
        message: String(err),
      });
    }
  };

  const validateJwt = async () => {
    if (!token) {
      alert("Chưa có JWT token.");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/auth/session/validate`, {
        method: "GET",
        headers: authHeaders(),
      });

      const data = await resp.json();

      if (resp.ok) {
        setCurrentUser(data.user);
      }

      show(data);
    } catch (err) {
      show({
        error: "Validate JWT failed",
        message: String(err),
      });
    }
  };

  const registerPasskey = async () => {
    if (!token) {
      alert("Cần login bằng password trước để đăng ký passkey.");
      return;
    }

    try {
      const optionsResp = await fetch(`${API_BASE}/auth/fido2/register/start`, {
        method: "POST",
        headers: authHeaders(),
      });

      const optionsJSON = await optionsResp.json();

      if (!optionsResp.ok) {
        show(optionsJSON);
        return;
      }

      const attResp = await startRegistration({ optionsJSON });

      const verifyResp = await fetch(`${API_BASE}/auth/fido2/register/finish`, {
        method: "POST",
        headers: jsonHeaders(),
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
        setCurrentUser(verifyJSON.user);
      }

      show(verifyJSON);
    } catch (err) {
      show({
        error: "Login with passkey failed",
        message: String(err),
      });
    }
  };

  const logout = async () => {
    if (!token) {
      alert("Chưa có token.");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        headers: authHeaders(),
      });

      const data = await resp.json();

      setToken("");
      setCurrentUser(null);
      setEmployees([]);
      setSelectedEmployee(null);
      setAdminStatus(null);

      show(data);
    } catch (err) {
      show({
        error: "Logout failed",
        message: String(err),
      });
    }
  };

  const loadEmployees = async () => {
    if (!token) {
      alert("Cần login trước.");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/api/v1/employees`, {
        method: "GET",
        headers: authHeaders(),
      });

      const data = await resp.json();

      if (resp.ok) {
        setEmployees(data.employees || []);
      }

      show(data);
    } catch (err) {
      show({
        error: "Load employees failed",
        message: String(err),
      });
    }
  };

  const loadEmployeeDetail = async (id) => {
    if (!token) {
      alert("Cần login trước.");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/api/v1/employees/${id}`, {
        method: "GET",
        headers: authHeaders(),
      });

      const data = await resp.json();

      if (resp.ok) {
        setSelectedEmployee(data);
      }

      show(data);
    } catch (err) {
      show({
        error: "Load employee detail failed",
        message: String(err),
      });
    }
  };

  const loadMyProfile = async () => {
    if (!token) {
      alert("Cần login trước.");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/api/v1/employees/me`, {
        method: "GET",
        headers: authHeaders(),
      });

      const data = await resp.json();

      if (resp.ok) {
        setSelectedEmployee(data);
      }

      show(data);
    } catch (err) {
      show({
        error: "Load my profile failed",
        message: String(err),
      });
    }
  };

  const updateProfileMassAssignment = async () => {
    if (!token) {
      alert("Cần login trước.");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/api/v1/employees/profile`, {
        method: "PATCH",
        headers: jsonHeaders(),
        body: JSON.stringify(profileForm),
      });

      const data = await resp.json();
      show(data);
    } catch (err) {
      show({
        error: "Update profile failed",
        message: String(err),
      });
    }
  };

  const exportPdf = async () => {
    if (!token) {
      alert("Cần login trước.");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/api/v1/tools/export-pdf`, {
        method: "POST",
        headers: jsonHeaders(),
        body: JSON.stringify({
          source_url: exportUrl,
        }),
      });

      const data = await resp.json();
      show(data);
    } catch (err) {
      show({
        error: "Export PDF failed",
        message: String(err),
      });
    }
  };

  const uploadCv = async () => {
    if (!token) {
      alert("Cần login trước.");
      return;
    }

    if (!cvFile) {
      alert("Chọn file CV trước.");
      return;
    }

    try {
      const formData = new FormData();
      formData.append("file", cvFile);

      const resp = await fetch(`${API_BASE}/api/v1/tools/upload-cv`, {
        method: "POST",
        headers: authHeaders(),
        body: formData,
      });

      const data = await resp.json();
      show(data);
    } catch (err) {
      show({
        error: "Upload CV failed",
        message: String(err),
      });
    }
  };

  const loadAdminStatus = async () => {
    if (!token) {
      alert("Cần login trước.");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/api/v1/admin/status`, {
        method: "GET",
        headers: authHeaders(),
      });

      const data = await resp.json();

      if (resp.ok) {
        setAdminStatus(data);
      }

      show(data);
    } catch (err) {
      show({
        error: "Load admin status failed",
        message: String(err),
      });
    }
  };

  const loadSecurityEvents = async () => {

    if (!token) {
      alert("Cần login trước.");
      return;
    }

    try {

      const resp = await fetch(
        `${API_BASE}/api/v1/security/events`,
        {
          method: "GET",
          headers: authHeaders(),
        }
      );

      const data = await resp.json();

      if (resp.ok) {
        setSecurityEvents(data.events || []);
      }

      show(data);

    } catch (err) {

      show({
        error: "Load security events failed",
        message: String(err),
      });

    }
  };

  const loadThreatEvents = async () => {

    if (!token) {
      alert("Cần login trước.");
      return;
    }

    try {

      const resp = await fetch(
        `${API_BASE}/api/v1/security/threats`,
        {
          method: "GET",
          headers: authHeaders(),
        }
      );

      const data = await resp.json();

      if (resp.ok) {
        setThreatEvents(data.threats || []);
      }

      show(data);

    } catch (err) {

      show({
        error: "Load threat events failed",
        message: String(err),
      });

    }
  };

  const loadIncidents = async () => {

      try {

          const resp = await fetch(
              `${API_BASE}/api/v1/security/incidents`,
              {
                  method: "GET",
                  headers: authHeaders(),
              }
          );

          const data = await resp.json();

          if (resp.ok) {
              setIncidents(
                  data.incidents || []
              );
          }

      } catch (err) {

          console.error(
              "Load incidents failed:",
              err
          );

      }
  };

  return (
    <div className="app">
      <header className="hero">
        <div>
          <p className="eyebrow">KMA Cyber Range</p>
          <h1>HR Management Security Lab</h1>
          <p>
            Frontend tối thiểu để demo HR System, JWT, FIDO2/WebAuthn, BOLA,
            Mass Assignment, SSRF, Upload CV và Admin Status.
          </p>
        </div>

        <div className="status-card">
          <p>API Gateway</p>
          <strong>{API_BASE}</strong>
          <span>Frontend luôn gọi qua WAF/Nginx</span>
        </div>
      </header>

      <main className="grid">
        <section className="card">
          <h2>1. Login / FIDO2</h2>

          <label>Username</label>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />

          <label>Password</label>
          <input
            value={password}
            type="password"
            onChange={(e) => setPassword(e.target.value)}
          />

          <div className="button-row">
            <button onClick={passwordLogin}>Password Login</button>
            <button onClick={registerPasskey}>Register Passkey</button>
            <button onClick={loginWithPasskey}>FIDO2 Login</button>
            <button onClick={validateJwt}>Validate JWT</button>
            <button className="danger" onClick={logout}>Logout</button>
          </div>

          <div className="mini-info">
            <p><strong>Current user:</strong> {currentUser ? `${currentUser.username} (${currentUser.role})` : "None"}</p>
            <p><strong>JWT:</strong> {token ? "Available" : "Not available"}</p>
          </div>
        </section>

        <section className="card">
          <h2>2. Dashboard</h2>

          <div className="dashboard">
            <div>
              <span>User</span>
              <strong>{currentUser?.username || "-"}</strong>
            </div>
            <div>
              <span>Role</span>
              <strong>{currentUser?.role || "-"}</strong>
            </div>
            <div>
              <span>Auth</span>
              <strong>{token ? "JWT Active" : "No Token"}</strong>
            </div>
            <div>
              <span>WAF</span>
              <strong>localhost:8080</strong>
            </div>
          </div>

          <p className="note">
            Gợi ý demo: login bằng <code>admin/admin123</code> để xem toàn bộ
            nhân sự. Login bằng <code>employee01/employee123</code> để demo
            BOLA và Mass Assignment.
          </p>
        </section>

        <section className="card wide">
          <h2>3. Employee List</h2>

          <div className="button-row">
            <button onClick={loadEmployees}>Load Employees</button>
            <button onClick={loadMyProfile}>My Profile</button>
          </div>

          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>User ID</th>
                <th>Full Name</th>
                <th>Department</th>
                <th>Position</th>
                <th>Salary</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {employees.map((emp) => (
                <tr key={emp.id}>
                  <td>{emp.id}</td>
                  <td>{emp.user_id}</td>
                  <td>{emp.full_name}</td>
                  <td>{emp.department}</td>
                  <td>{emp.position}</td>
                  <td>{emp.salary}</td>
                  <td>
                    <button onClick={() => loadEmployeeDetail(emp.id)}>
                      Detail
                    </button>
                  </td>
                </tr>
              ))}

              {employees.length === 0 && (
                <tr>
                  <td colSpan="7" className="empty">
                    Chưa có dữ liệu. Bấm Load Employees.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </section>

        <section className="card">
          <h2>4. Employee Detail</h2>

          {selectedEmployee ? (
            <pre>{JSON.stringify(selectedEmployee, null, 2)}</pre>
          ) : (
            <p className="empty">Chưa chọn nhân sự.</p>
          )}
        </section>

        <section className="card">
          <h2>5. Update Profile / Mass Assignment</h2>

          <label>Full name</label>
          <input
            value={profileForm.full_name}
            onChange={(e) =>
              setProfileForm({ ...profileForm, full_name: e.target.value })
            }
          />

          <label>Phone</label>
          <input
            value={profileForm.phone}
            onChange={(e) =>
              setProfileForm({ ...profileForm, phone: e.target.value })
            }
          />

          <label>Email</label>
          <input
            value={profileForm.email}
            onChange={(e) =>
              setProfileForm({ ...profileForm, email: e.target.value })
            }
          />

          <label>Role field, intentional vulnerability</label>
          <input
            value={profileForm.role}
            onChange={(e) =>
              setProfileForm({ ...profileForm, role: e.target.value })
            }
          />

          <button onClick={updateProfileMassAssignment}>
            PATCH /employees/profile
          </button>

          <p className="note">
            Đây là phần demo Mass Assignment: user thường gửi thêm
            <code> role=admin </code> để leo thang quyền.
          </p>
        </section>

        <section className="card">
          <h2>6. Export PDF / SSRF Lab</h2>

          <label>source_url</label>
          <input
            value={exportUrl}
            onChange={(e) => setExportUrl(e.target.value)}
          />

          <button onClick={exportPdf}>Export PDF</button>

          <p className="note">
            Payload nội bộ nên dùng: <code>http://kma-app:8000/health</code>.
            Payload metadata có thể bị WAF chặn.
          </p>
        </section>

        <section className="card">
          <h2>7. Upload CV</h2>

          <input
            type="file"
            onChange={(e) => setCvFile(e.target.files?.[0] || null)}
          />

          <button onClick={uploadCv}>Upload CV</button>

          <p className="note">
            Endpoint này dùng cho kịch bản upload CV/RAG poisoning surface.
          </p>
        </section>

        <section className="card">
          <h2>8. Admin System Status</h2>

          <button onClick={loadAdminStatus}>Load Admin Status</button>

          {adminStatus ? (
            <pre>{JSON.stringify(adminStatus, null, 2)}</pre>
          ) : (
            <p className="empty">Chưa tải trạng thái hệ thống.</p>
          )}
        </section>

<section className="card wide">

  <h2>9. Security Dashboard</h2>

  <div className="button-row">

    <button onClick={loadSecurityEvents}>
      Load Security Events
    </button>

    <button onClick={loadThreatEvents}>
      Load Threat Events
    </button>

    <button onClick={loadAiAnalysis}>
      Load AI Analysis
    </button>

  </div>

  <h3>
     Live Events ({securityEvents.length})
  </h3>

  <table>

    <thead>
      <tr>
        <th>Time</th>
        <th>Event</th>
        <th>Severity</th>
        <th>User</th>
      </tr>
    </thead>

    <tbody>

      {securityEvents.map((e, i) => (

        <tr key={i}>
          <td>{e.timestamp}</td>
          <td>{e.event}</td>
          <td>{e.severity}</td>
          <td>{e.user}</td>
        </tr>

      ))}

    </tbody>

  </table>

  <h3>
     Attack Timeline ({threatEvents.length})
  </h3>

  <table>

    <thead>
      <tr>
        <th>Time</th>
        <th>Attack</th>
        <th>Severity</th>
        <th>User</th>
      </tr>
    </thead>

    <tbody>

      {threatEvents.map((e, i) => (

        <tr key={i}>
          <td>{e.timestamp}</td>
          <td>{e.attack}</td>
          <td>{e.severity}</td>
          <td>{e.user}</td>
        </tr>

      ))}

    </tbody>

  </table>

<h3>AI Analysis</h3>

<hr />

<h3>General Information</h3>

<p>
  <b>Incident ID:</b>{" "}
  {aiResult?.incident_id ?? "-"}
</p>

<p>
  <b>Severity:</b>
  {" "}
  <span
    style={{
      fontWeight: "bold",
      color:
        aiResult?.severity === "critical"
          ? "red"
          : aiResult?.severity === "high"
          ? "orange"
          : aiResult?.severity === "medium"
          ? "gold"
          : aiResult?.severity === "low"
          ? "#2ecc71"
          : "#888"
    }}
  >
    {aiResult?.severity
      ? aiResult.severity.toUpperCase()
      : "UNKNOWN"}
  </span>
</p>

<p>
  <b>Confidence:</b>{" "}
  {
     aiResult?.confidence != null
         ? `${Math.round(aiResult.confidence * 100)}%`
         : "-"
  }
</p>

<p>
  <b>Processing Time:</b>{" "}
  {
      aiResult?.processing_time_ms != null
          ? `${Math.round(aiResult.processing_time_ms)} ms`
          : "-"
  }

</p>

<p>
  <b>SOAR Action:</b>{" "}
  {aiResult?.action_taken ?? "-"}
</p>

<hr />

<h3>Threat Intelligence</h3>

<p>
  <b>MITRE:</b>
  {" "}
  {aiResult?.mitre?.join(", ")
    || "none"}
</p>

<p>
  <b>Attack Chain:</b>
</p>

<p>
  {aiResult?.attack_chain?.join(" → ")
    || "No attack chain detected"}
</p>

<h3>Attack Phase</h3>

<p>
  <b>Current Stage:</b>
  {" "}
  {aiResult?.phase?.current_phase}
</p>

<p>
  {aiResult?.phase?.phase_name}
</p>

<p>

  [

  {aiResult?.phase?.current_phase >= 1 ? "██" : "░░"}
  {aiResult?.phase?.current_phase >= 2 ? "██" : "░░"}
  {aiResult?.phase?.current_phase >= 3 ? "██" : "░░"}
  {aiResult?.phase?.current_phase >= 4 ? "██" : "░░"}
  {aiResult?.phase?.current_phase >= 5 ? "██" : "░░"}

  ]

  {" "}
  {aiResult?.phase?.attack_progress}

</p>

<hr />

<h3>
  Attack Summary
</h3>

<p>
  {aiResult?.summary}
</p>

<h3>
  Attacker Profile
</h3>

<p>
  {aiResult?.profile}
</p>

<hr />

<h3>
  Attack Timeline
</h3>

{
  aiResult?.timeline?.length > 0
    ? aiResult.timeline.map(
        (item, idx) => (

          <p key={idx}>

            <b>{item.timestamp}</b>

            {" | "}

            {item.name}

            {" | "}

            {item.stage}

            {" | "}

            {item.severity}

            {" | "}

            {item.source_ip}

          </p>

        )
      )
    : (
        <p>
          No timeline available
        </p>
      )
}

<hr />

<h3>SOAR Response</h3>

<ul
  style={{
    textAlign: "left",
    width: "fit-content",
    margin: "0 auto"
  }}
>
{
  aiResult?.response_actions?.length > 0
    ? aiResult.response_actions.map(
        (item, index) => (
          <li key={index}>
            ✓ {item}
          </li>
        )
      )
    : (
      <li>No recommendations available</li>
    )
}
</ul>

<hr />

<h3>Investigation Notes</h3>

<ul>

{
    aiResult?.investigation_notes?.length > 0

        ? aiResult.investigation_notes.map(
            (
                note,
                idx
            ) => (

                <li key={idx}>
                    {note}
                </li>

            )
        )

        : (

            <li>
                No investigation notes.
            </li>

        )

}

</ul>

<h3>
  Incident Memory ({incidents.length})
</h3>

{
  incidents.length > 0
    ? incidents.slice(0, 5).map((incident) => (

        <div
          key={incident.incident_id}
          style={{
            border: "1px solid #444",
            padding: "10px",
            marginBottom: "10px"
          }}
        >

          <p>
            <b>ID:</b> {incident.incident_id}
          </p>

          <p>
            <b>Severity:</b>{" "}

            <span
              style={{
                fontWeight: "bold",
                color:
                  incident.severity === "critical"
                    ? "red"
                    : incident.severity === "high"
                    ? "orange"
                    : incident.severity === "medium"
                    ? "gold"
                    : "lime"
              }}
            >
              {incident.severity?.toUpperCase()}
            </span>

          </p>

          <p>
            <b>Events:</b> {incident.events}
          </p>

          <p>
            <b>Created:</b> {incident.created_at}
          </p>

        </div>

      ))
    : (
        <p>No incidents found.</p>
      )
}

<h3>
  SIEM Alerts
</h3>

{
  aiResult?.siem_alerts?.map(
    (
      alert,
      idx
    ) => (

      <p key={idx}>

        {alert.rule}

        {" | Level "}

        {alert.level}

      </p>

    )
  )
}

</section>

        <section className="card wide">
          <h2>Result / API Response</h2>
          <pre className="result">{result || "Chưa có response."}</pre>
        </section>
      </main>
    </div>
  );
}

export default App;
