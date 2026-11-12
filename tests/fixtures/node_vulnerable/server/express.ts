import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { Order, User } from "./models";
import invoicesRouter from "./routes/invoices";

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  req.user = jwt.verify(token, process.env.JWT_SECRET);
  next();
}

app.post("/api/orders", async (req, res) => {
  const order = await Order.create(req.body);
  res.status(201).json(order);
});

app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

app.put("/api/users/:id/role", requireAuth, async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { role: req.body.role });
  res.json({ ok: true });
});

app.get("/api/me/orders", async (req, res) => {
  const userId = req.headers["x-user-id"];
  const orders = await Order.find({ owner: userId });
  res.json(orders);
});

app.use("/api/invoices", invoicesRouter);

app.listen(3001);
