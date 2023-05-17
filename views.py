
from reportlab.lib.units import inch, cm
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
import io
from django.core.mail import send_mail
import dataclasses
from django.http import FileResponse
from reportlab.lib.pagesizes import letter, A4
from django.core.mail import EmailMessage
from reportlab.pdfgen import canvas
from django.conf import settings
from io import BytesIO
from PIL import Image
from django.shortcuts import render, HttpResponse, redirect
import requests
from .models import User, Customer, Transactions
from .serializers import AdminRegistrationSerializer, AdminLoginSerializers, CustomerSerializer, UserSerializer, TransactionsSerializer, CustomerLoginSerializer, CustomerBalanceSerializer, TransactionsFilterSerializer
from rest_framework import generics, permissions
from rest_framework.response import Response
from django.contrib.auth import authenticate, login
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.contrib.auth.models import update_last_login
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, views
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.decorators import login_required
from rest_framework.renderers import HTMLFormRenderer, TemplateHTMLRenderer
from django_filters.rest_framework import DjangoFilterBackend


def home(request):
    return render(request, 'home.html')


def admin(request):
    return render(request, "Admin.html")


def customer(request):
    return render(request, 'Customer.html')


def adminregister(request):
    return render(request, "adminregister.html")


def adminlogin(request):
    return render(request, "adminlogin.html")


def admindetails(request):
    return render(request, "AdminDetails.html")


def customer(request):
    return render(request, "Customer.html")


def customerdetails(request):
    return render(request, "CustomerDetails.html")


def customerlogin(request):
    return render(request, "customerlogin.html")


def customerpage(request):
    return render(request, "Customerpage.html")


def customertransaction(request):
    return render(request, "customertransaction.html")


def customerbalance(request):
    return render(request, "customerbalance.html")


def transactions(request):
    return render(request, "TransactionsDetails.html")


def transactionsfilter(request):
    return render(request, "transactionsfilter.html")


def customertransactionsfilter(request):
    return render(request, "customertransactionsfilter.html")


def card(request):
    return render(request, "card.html")


class AdminRegisterApi(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = AdminRegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "user": UserSerializer(user,    context=self.get_serializer_context()).data,
            "message": "User Created Successfully.  Now perform Login to get your token",
        })


class AdminLoginApiView(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = AdminLoginSerializers

    def post(self, request, *args, **kwargs):
        serializer = AdminLoginSerializers(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        update_last_login(None, user)
        refresh = RefreshToken.for_user(user)
        return Response({
            "message": "Login Successfully.  Now Open Your Portal",
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })


class CustomerView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [JWTAuthentication]

    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    filter_backends = [DjangoFilterBackend]


class CustomerEditView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [JWTAuthentication]
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    lookup_field = 'id'


class TransactionsView(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [JWTAuthentication]
    queryset = Transactions.objects.all()
    serializer_class = TransactionsSerializer


class CustomerLogin(generics.GenericAPIView):
    queryset = Customer.objects.all()
    serializer_class = CustomerLoginSerializer

    def post(self, request, *args, **kwargs):
        # import pdb
        # pdb.set_trace()
        account_number = request.data.get('account_number')
        password = request.data.get('password')
        try:
            customer = Customer.objects.get(account_number=account_number)
            if customer.Password == password:
                request.session['customer_id'] = customer.id
                print("Your Customer ID", customer.id)
                return Response({"messgae": "succesfully Login"})
            else:
                return Response({"message": "Failed to login"})
        except:
            Customer.DoesNotExist
            return HttpResponse("error")


def invoice_pdf_format(request):
    customer_id = request.session.get('customer_id')
    sender = Customer.objects.get(id=customer_id).account_number
    invoices = Transactions.objects.filter(
        sender_account_number=sender)
    print(invoices)
    buffer = io.BytesIO()

    p = canvas.Canvas(buffer, pagesize=letter, bottomup=0)

    text_object = p.beginText()
    text_object.setTextOrigin(inch, inch)

    lines = [
        'Your Account Number : ' +
        Customer.objects.get(id=customer_id).account_number,
        'Transaction Status : SUCCESS'
        " ", " ", " ", " ", " ",
    ]
    for invoice in invoices:
        lines.append(str(invoice.sender_account_number))
        lines.append(str(invoice.ammount))
        lines.append(str(invoice.reciver_account_number))
        lines.append(' ')
        lines.append(
            '=====================================================================')
        lines.append(' ')
        invoice.save()

    for line in lines:
        text_object.textLine(line)

    p.drawText(text_object)
    p.showPage()
    p.save()
    pdf = buffer.getvalue()
    buffer.close()
    return pdf


class CustomerTransaction(generics.GenericAPIView):

    queryset = Transactions.objects.all()
    serializer_class = TransactionsSerializer

    def post(self, request, *args, **kwargs):
        sender_account_number = request.data.get('sender_account_number')
        ammount = float(request.data.get('ammount'))
        reciver_account_number = request.data.get('reciver_account_number')
        date_of_transaction = request.data.get('date_of_transaction')

        sender = Customer.objects.get(account_number=sender_account_number)
        customer_id = request.session.get('customer_id')

        if sender.id != customer_id:
            return Response({"Meesage": "Wrong Account Number"})
        else:
            pass

        reciver = Customer.objects.get(
            account_number=reciver_account_number)

        if sender.Balance < ammount:
            return Response({"msg": "Low Balance !"})

        sender.Balance -= ammount
        reciver.Balance += ammount

        transactions = Transactions(
            sender_account_number=sender, ammount=ammount, reciver_account_number=reciver, date_of_transaction=date_of_transaction)
        transactions.save()

        sender.save()
        reciver.save()
        invoice_pdf_format(request)

        def testemail():
            subject = "Transactions Invoice"
            message = "Happy Transactions"
            reply_to_list = [sender.Email]

            email = EmailMessage(subject, message, 'ant@a.com', reply_to_list)
            pdf = invoice_pdf_format(request)
            email.attach('invoice.pdf', pdf, 'application/pdf')
            try:
                email.send(fail_silently=False)
                return HttpResponse("Mail Sent")
            except:
                return HttpResponse("Mail Not Sent")

        testemail()

        serializer = self.get_serializer(transactions)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CustomerBalance(generics.ListAPIView):

    def list(self, request):
        customer_id = request.session.get('customer_id')
        queryset = Customer.objects.all()
        if customer_id is not None:
            queryset = queryset.get(id=customer_id)
            serializer = CustomerBalanceSerializer(queryset, many=False)
            return Response(serializer.data)
        else:
            # serializer = CustomerBalanceSerializer(queryset, many=True)
            # return Response(serializer.data)
            return Response({"msg": "Please login in to check balance"})


class TransactionFilter(generics.GenericAPIView):
    queryset = Transactions.objects.all()
    serializer_class = TransactionsFilterSerializer

    def post(self, request, *args, **kwargs):
        start_date = request.data.get('start_date_of_transaction')
        end_date = request.data.get('end_date_of_transaction')
        year = request.data.get('year')
        month = request.data.get('month')
        queryset = Transactions.objects.all()
        if start_date and end_date:
            queryset = queryset.filter(
                date_of_transaction__range=(start_date, end_date)).order_by('date_of_transaction')
        elif year:
            queryset = queryset.filter(
                date_of_transaction__year=year).order_by('date_of_transaction')
        elif month:
            queryset = queryset.filter(
                date_of_transaction__month=month).order_by('date_of_transaction')

        serializer = TransactionsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)


class CustomerTransactionFilter(generics.GenericAPIView):
    queryset = Transactions.objects.all()
    serializer_class = TransactionsFilterSerializer

    def post(self, request):
        customer_id = request.session.get('customer_id')
        sender_account = Customer.objects.get(id=customer_id)
        queryset = Transactions.objects.all()
        queryset = queryset.filter(sender_account_number=sender_account)
        start_date = request.data.get('start_date_of_transaction')
        end_date = request.data.get('end_date_of_transaction')
        year = request.data.get('year')
        month = request.data.get('month')
        if start_date and end_date:
            queryset = queryset.filter(
                date_of_transaction__range=(start_date, end_date)).order_by('date_of_transaction')
        elif year:
            queryset = queryset.filter(
                date_of_transaction__year=year).order_by('date_of_transaction')
        elif month:
            queryset = queryset.filter(
                date_of_transaction__month=month).order_by('date_of_transaction')

        serializer = TransactionsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)
