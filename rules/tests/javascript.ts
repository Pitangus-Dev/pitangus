"use client";
import { createClient } from "@supabase/supabase-js";
import express from "express";
import { decodeJwt } from "jose";

// ruleid: appsec.js.supabase-service-role-in-client
export const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
// ok: appsec.js.supabase-service-role-in-client
export const browser = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

export function role(token: string) {
  // ruleid: appsec.js.jwt-decode-unverified
  return decodeJwt(token).role;
}

const router = express.Router();
router.get("/me", requireAuth, (req, res) => res.json(req.user));
router.post("/orders", requireAuth, (req, res) => res.json({}));
// ruleid: appsec.js.route-without-auth
router.delete("/orders/:id", (req, res) => res.json({}));
// ok: appsec.js.route-without-auth
router.post("/login", (req, res) => res.json({}));
// ok: appsec.js.route-without-auth
router.get("/health", (req, res) => res.send("ok"));
