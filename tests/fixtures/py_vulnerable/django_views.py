from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from rest_framework import serializers, viewsets
from rest_framework.permissions import IsAuthenticated

from .models import Invoice, PaymentMethod, User


@require_POST
def delete_account(request):
    User.objects.filter(id=request.POST["user_id"]).delete()
    return JsonResponse({"ok": True})


@login_required
def invoice_detail(request, pk):
    invoice = Invoice.objects.get(pk=pk)
    return JsonResponse({"number": invoice.number, "total": str(invoice.total)})


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = "__all__"


class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer


class PaymentMethodViewSet(viewsets.ModelViewSet):
    queryset = PaymentMethod.objects.all()
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated]
