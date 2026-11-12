import { Invoice } from "../models";

export async function listInvoices(req, res) {
  res.json(await Invoice.find({ owner: req.user.id }));
}

export async function deleteInvoice(req, res) {
  const deleted = await Invoice.findOneAndDelete({ _id: req.params.id, owner: req.user.id });
  if (!deleted) return res.status(404).end();
  res.status(204).end();
}
