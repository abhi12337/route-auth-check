import express from "express";
import cors from "cors";
import { requireAuth, requireAdmin } from "./middleware/auth";
import { Order, User } from "./models";
import invoicesRouter from "./routes/invoices";
import authRouter from "./routes/auth";

const app = express();
app.use(express.json());
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));

app.use("/api/auth", authRouter);

app.post("/api/orders", requireAuth, async (req, res) => {
  const { items, address } = req.body;
  const order = await Order.create({ items, address, owner: req.user.id });
  res.status(201).json(order);
});

app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, owner: req.user.id });
  if (!order) return res.status(404).end();
  res.json(order);
});

app.put("/api/users/:id/role", requireAuth, requireAdmin, async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { role: req.body.role });
  res.json({ ok: true });
});

app.get("/api/me/orders", requireAuth, async (req, res) => {
  const orders = await Order.find({ owner: req.user.id });
  res.json(orders);
});

app.use("/api/invoices", requireAuth, invoicesRouter);

app.listen(3001);
