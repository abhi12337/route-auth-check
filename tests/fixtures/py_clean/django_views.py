from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_POST
from rest_framework import serializers, viewsets
from rest_framework.permissions import IsAuthenticated

from .models import Invoice, PaymentMethod


@require_POST
@login_required
def delete_account(request):
    request.user.delete()
    return JsonResponse({"ok": True})


@login_required
def invoice_detail(request, pk):
    invoice = get_object_or_404(Invoice, pk=pk, owner=request.user)
    return JsonResponse({"number": invoice.number, "total": str(invoice.total)})


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ["id", "number", "total", "owner"]
        read_only_fields = ["id", "owner"]


class InvoiceViewSet(viewsets.ModelViewSet):
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Invoice.objects.filter(owner=self.request.user)


class PaymentMethodViewSet(viewsets.ModelViewSet):
    queryset = PaymentMethod.objects.all()
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated, IsOwner]
