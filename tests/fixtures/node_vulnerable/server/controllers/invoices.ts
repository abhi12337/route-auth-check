import { Invoice } from "../models";

export async function listInvoices(req, res) {
  res.json(await Invoice.find({ public: true }));
}

export async function deleteInvoice(req, res) {
  await Invoice.findByIdAndDelete(req.params.id);
  res.status(204).end();
}
