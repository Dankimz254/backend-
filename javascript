</>  javaScript

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const cors = require("cors");

const app = express();

app.set("trust proxy", 1);
app.use(express.json());

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));

app.use(session({
  name: "novaai.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 60 * 60 * 1000
  }
}));

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.DERIV_CLIENT_ID;
const REDIRECT_URI = process.env.DERIV_REDIRECT_URI;

const AUTH_URL = "https://auth.deriv.com/oauth2/auth";
const TOKEN_URL = "https://auth.deriv.com/oauth2/token";
const API_URL = "https://api.derivws.com";

function requireConfig() {
  if (!CLIENT_ID || !REDIRECT_URI || !process.env.SESSION_SECRET) {
    throw new Error("Missing required environment variables.");
  }
}

function randomString(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function createChallenge(verifier) {
  return crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
}

function requireLogin(req, res, next) {
  if (!req.session.derivAccessToken) {
    return res.status(401).json({
      error: "Please connect your Deriv account first."
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.send(`
    <h1>NovaAI Backend</h1>
    <p>Backend is running.</p>
    <p><a href="/health">Check server health</a></p>
  `);
});

app.get("/health", (req, res) => {
  res.json({
    status: "online",
    application: "NovaAI",
    time: new Date().toISOString()
  });
});

// Start Deriv OAuth login
app.get("/auth/deriv", (req, res) => {
  try {
    requireConfig();

    const state = randomString(32);
    const verifier = randomString(64);
    const challenge = createChallenge(verifier);

    req.session.oauthState = state;
    req.session.codeVerifier = verifier;

    const params = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: process.env.DERIV_SCOPES || "trade account_manage",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    // Optional partner attribution for sign-ups.
    if (process.env.DERIV_TRACKING_TOKEN) {
      params.set(
        process.env.DERIV_TRACKING_PARAMETER || "t",
        process.env.DERIV_TRACKING_TOKEN
      );
    }

    if (process.env.DERIV_AFFILIATE_ID) {
      params.set("utm_source", process.env.DERIV_AFFILIATE_ID);
      params.set("utm_medium", "affiliate");
      params.set(
        "utm_campaign",
        process.env.DERIV_CAMPAIGN || "novaai"
      );
    }

    res.redirect(`${AUTH_URL}?${params.toString()}`);

  } catch (error) {
    console.error(error.message);
    res.status(500).send("OAuth configuration is incomplete.");
  }
});

// Optional registration route
app.get("/auth/deriv/register", (req, res) => {
  try {
    requireConfig();

    const state = randomString(32);
    const verifier = randomString(64);
    const challenge = createChallenge(verifier);

    req.session.oauthState = state;
    req.session.codeVerifier = verifier;

    const params = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: process.env.DERIV_SCOPES || "trade account_manage",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
      prompt: "registration"
    });

    if (process.env.DERIV_TRACKING_TOKEN) {
      params.set(
        process.env.DERIV_TRACKING_PARAMETER || "t",
        process.env.DERIV_TRACKING_TOKEN
      );
    }

    if (process.env.DERIV_AFFILIATE_ID) {
      params.set("utm_source", process.env.DERIV_AFFILIATE_ID);
      params.set("utm_medium", "affiliate");
      params.set(
        "utm_campaign",
        process.env.DERIV_CAMPAIGN || "novaai"
      );
    }

    res.redirect(`${AUTH_URL}?${params.toString()}`);

  } catch (error) {
    console.error(error.message);
    res.status(500).send("Registration configuration is incomplete.");
  }
});

// Deriv sends the user back here after login
app.get("/auth/deriv/callback", async (req, res) => {
  try {
    requireConfig();

    if (req.query.error) {
      return res.status(400).send(
        "Deriv login was cancelled or denied. You can return to NovaAI and try again."
      );
    }

    const { code, state } = req.query;

    if (
      !code ||
      !state ||
      !req.session.oauthState ||
      state !== req.session.oauthState ||
      !req.session.codeVerifier
    ) {
      return res.status(400).send("Invalid OAuth state. Please try again.");
    }

    const verifier = req.session.codeVerifier;

    delete req.session.oauthState;
    delete req.session.codeVerifier;

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code,
      code_verifier: verifier,
      redirect_uri: REDIRECT_URI
    });

    const response = await fetch(TOKEN_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    });

    const tokenData = await response.json();

    if (!response.ok || !tokenData.access_token) {
      console.error("Deriv token exchange failed:", response.status);
      return res.status(400).send(
        "Deriv authorization could not be completed. Please try again."
      );
    }

    req.session.derivAccessToken = tokenData.access_token;
    req.session.tokenExpiresAt =
      Date.now() + Number(tokenData.expires_in || 0) * 1000;

    req.session.save((error) => {
      if (error) {
        console.error("Session save failed:", error.message);
        return res.status(500).send("Could not save your login session.");
      }

      res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>NovaAI Connected</title></head>
        <body style="background:#08101e;color:white;font-family:Arial;text-align:center;padding:50px">
          <h1 style="color:#e8b84d">NovaAI</h1>
          <h2>Deriv connection successful</h2>
          <p>Your account has been authorised.</p>
          <a href="/" style="color:#e8b84d">Return to NovaAI</a>
        </body>
        </html>
      `);
    });

  } catch (error) {
    console.error("OAuth callback error:", error.message);
    res.status(500).send("An error occurred during Deriv login.");
  }
});

// Get accounts connected to this OAuth session
app.get("/api/deriv/accounts", requireLogin, async (req, res) => {
  try {
    const response = await fetch(
      `${API_URL}/trading/v1/options/accounts`,
      {
        headers: {
          Authorization: `Bearer ${req.session.derivAccessToken}`
        }
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: "Could not retrieve Deriv accounts."
      });
    }

    res.json(data);

  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Account request failed." });
  }
});

// Get a short-lived authenticated WebSocket URL for one account
app.post(
  "/api/deriv/accounts/:accountId/otp",
  requireLogin,
  async (req, res) => {
    try {
      const accountId = req.params.accountId;

      if (!/^[a-zA-Z0-9_-]+$/.test(accountId)) {
        return res.status(400).json({ error: "Invalid account ID." });
      }

      const response = await fetch(
        `${API_URL}/trading/v1/options/accounts/${encodeURIComponent(accountId)}/otp`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${req.session.derivAccessToken}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({})
        }
      );

      const data = await response.json();

      if (!response.ok) {
        return res.status(response.status).json({
          error: "Could not prepare the Deriv account connection."
        });
      }

      res.json(data);

    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: "WebSocket preparation failed." });
    }
  }
);

// Disconnect the Deriv session
app.post("/api/deriv/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("novaai.sid");
    res.json({ status: "disconnected" });
  });
});

app.listen(PORT, () => {
  console.log(`NovaAI backend running on port ${PORT}`);
});
