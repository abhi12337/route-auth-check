import { Router } from "express";
import { listInvoices, deleteInvoice } from "../controllers/invoices";

const router = Router();

router.get("/", listInvoices);
router.delete("/:id", deleteInvoice);

export default router;
