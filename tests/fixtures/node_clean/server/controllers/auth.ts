import { User } from "../models";
import { issueToken, checkPassword, hashPassword } from "../lib/tokens";

export async function login(req, res) {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await checkPassword(password, user.passwordHash))) return res.status(401).end();
  res.json({ token: issueToken(user) });
}

export async function signup(req, res) {
  const { email, password } = req.body;
  const user = await User.create({ email, passwordHash: await hashPassword(password), role: "member" });
  res.status(201).json({ id: user.id });
}
