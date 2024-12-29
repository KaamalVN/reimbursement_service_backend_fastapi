from fastapi import APIRouter, HTTPException, Depends, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from io import StringIO
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.sql import text
from datetime import datetime, timedelta
import jwt, time
from werkzeug.security import generate_password_hash
from pydantic import BaseModel
from typing import List
from .database import get_db, insert_company, insert_user, get_roles_by_company, add_role, delete_role, populate_roles_and_employees, get_requests_by_employee, get_previous_approver_status, create_reimbursement_request, get_approval_hierarchy, create_approval_workflow, handle_approval_rejection
from .models import User, Employees, Role, Company, ReimbursementRequest
from .config import Config  # Ensure you have this in your config
from .utils import create_email_body, send_email, generate_random_password, send_bulk_emails, send_email_duplicate

router = APIRouter()
SECRET_KEY = Config.SECRET_KEY
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # Define the token URL

class LoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    token: str
    user: dict

class CompanyCreate(BaseModel):
    companyName: str
    address: str
    contactEmail: str
    adminEmail: str

class RoleCreate(BaseModel):
    roleName: str
    companyID: int
    permissionLevel: int

class RoleResponse(BaseModel):
    RoleID: int
    RoleName: str
    PermissionLevel: int

class CompanyResponse(BaseModel):
    companyName: str
    companyEmail: str
    companyAddress: str

class Manager(BaseModel):
    companyEmployeeID: int
    name: str

class CompanyIDRequest(BaseModel):
    companyID: int

class EmployeeResponse(BaseModel):
    companyEmployeeID: int
    name: str
    email: str
    roleName: str
    manager: dict = None  # Optional manager field

class GetReimbursementRequestsRequest(BaseModel):
    companyID: int
    employeeID: int

class MyTeamRequestsRequest(BaseModel):
    EmployeeID: int

class ReimbursementRequestResponse(BaseModel):
    RequestID: int
    EmployeeID: int
    CompanyEmployeeID: str
    CompanyID: int
    ExpenseTypes: List[str]
    Amounts: List[float]
    TravelStartDate: str
    TravelEndDate: str
    Purpose: str
    Description: str
    Receipts: List[str]
    Status: str
    SubmissionDate: str

class ReimbursementRequestCreate(BaseModel):
    EmployeeID: int
    CompanyID: int
    ExpenseTypes: List[str]
    Amounts: List[float]
    TravelStartDate: str
    TravelEndDate: str
    Purpose: str
    Description: str
    Receipts: List[str]

class ApproveRejectRequest(BaseModel):
    RequestID: int
    Action: str
    EmployeeID: int

@router.get("/test-db")
def test_db_connection(db: Session = Depends(get_db)):
    try:
        # Use SQLAlchemy's text() function for raw SQL queries
        result = db.execute(text("SHOW TABLES"))
        tables = [row[0] for row in result.fetchall()]
        return {"message": "Database connection successful!", "tables": tables}
    except Exception as e:
        return {"error": str(e)}

@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    email = request.email
    password = request.password

    print(f"Received login request for email: {email}")  # Log the received email

    # Check if the user is the fixed product admin
    if email == 'admin@reimburse.com' and password == 'admin2311':
        token = jwt.encode(
            {
                'email': email,
                'role_id': 'productAdmin',
                'exp': datetime.utcnow() + timedelta(hours=1)
            },
            SECRET_KEY,
            algorithm='HS256'
        )
        print('Generated Token for Product Admin:', token)  # Log the generated token
        return {'token': token, 'user': {'email': email, 'name': 'Product Admin', 'role_id': 'productAdmin'}}

    # For other users, query the database
    user = db.query(User).filter_by(Email=email).first()  # Fetch user by email
    print(f"User found in database: {user}")  # Log the user object (it will print None if not found)

    # Validate user and password
    if user:
        print(f"User role: {user.Role}, Company ID: {user.CompanyID}")  # Log user role and company ID
        if user.verify_password(password):  # Use the verify_password method
            if user.Role == 'companyAdmin':
                # Handle companyAdmin login
                token = jwt.encode(
                    {
                        'email': email,
                        'role_id': user.Role,
                        'company_id': user.CompanyID,
                        'exp': datetime.utcnow() + timedelta(hours=1)
                    },
                    SECRET_KEY,
                    algorithm='HS256'
                )
                print('Generated Token for Company Admin:', token)  # Log the generated token
                return {'token': token, 'user': {'email': email, 'role_id': user.Role, 'company_id': user.CompanyID}}

            elif user.Role == 'Employee':
                # Handle employee login
                employee = db.query(Employees).filter_by(Email=email, CompanyID=user.CompanyID).first()
                
                if employee:
                    # Fetch role details from the roles table
                    role = db.query(Role).filter_by(RoleID=employee.RoleID).first()
                    if role:
                        token = jwt.encode(
                            {
                                'email': email,
                                'role_id': employee.RoleID,
                                'employee_id': employee.EmployeeID,
                                'permission_level': role.PermissionLevel,
                                'company_id': user.CompanyID,
                                'exp': datetime.utcnow() + timedelta(hours=1)
                            },
                            SECRET_KEY,
                            algorithm='HS256'
                        )
                        print('Generated Token for Employee:', token)  # Log the generated token
                        return {'token': token, 'user': {'email': email, 'role_id': employee.RoleID, 'employee_id': employee.EmployeeID, 'permission_level': role.PermissionLevel, 'company_id': user.CompanyID}}

                print(f"No employee found for email: {email} in company ID: {user.CompanyID}")  # Log if no employee found
            else:
                print(f"Invalid role for user: {email}")  # Log if the role is not recognized
        else:
            print(f"Invalid password for user: {email}")  # Log invalid password attempt
    else:
        print(f"No user found for email: {email}")  # Log if no user is found

    raise HTTPException(status_code=401, detail='Invalid credentials')

@router.get("/validate-token")
async def validate_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization header is missing")
    
    try:
        # Decode the token
        decoded = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        
        # Assuming your token contains 'role_id' and 'company_id'
        if decoded.get('role_id') == 'productAdmin':
            company_id = ''  # Set to empty string for Product Admin
        else:
            company_id = decoded.get('company_id')  # Use company_id for other roles
        
        # Return user details
        return {
            "user": {
                "email": decoded.get('email'),
                "role_id": decoded.get('role_id'),
                "company_id": company_id,
            }
        }
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError as e:
        print(f"Invalid token error: {str(e)}")  # Log the specific error
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@router.post("/create-company")
def create_company(data: CompanyCreate, db: Session = Depends(get_db)):
    company_name = data.companyName
    address = data.address
    contact_email = data.contactEmail
    admin_email = data.adminEmail

    # Generate a password for the company admin
    admin_password = generate_random_password(length=12)
    hashed_password = generate_password_hash(admin_password)

    # Insert company into the database
    company_id = insert_company(company_name, address, contact_email, db)

    # Insert user as the company admin
    insert_user(db, admin_email, hashed_password, 'companyAdmin', company_id)

    # Prepare the email content
    subject = "Your Company Account Credentials"
    body = create_email_body(company_name, admin_email, admin_password)

    # Send the email with login credentials
    try:
        send_email(admin_email, subject, body)
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return {"message": "Company created but failed to send email."}, 201

    return {"message": "Company created successfully!"}, 201

@router.get("/companies")
def get_companies(db: Session = Depends(get_db)):
    companies = db.query(Company).all()  # Fetch all companies from the database
    company_list = [
        {
            'companyID': company.CompanyID,
            'companyName': company.CompanyName,
            'address': company.Address,
            'contactEmail': company.ContactEmail,
            'createdAt': company.CreatedAt
        }
        for company in companies
    ]
    return company_list  # Return the list of companies

@router.get("/company/{company_id}", response_model=CompanyResponse)
def get_company_details(company_id: int, db: Session = Depends(get_db)):
    company = db.query(Company).filter_by(CompanyID=company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    return {
        "companyName": company.CompanyName,
        "companyEmail": company.ContactEmail,
        "companyAddress": company.Address,
    }

@router.get("/roles/{company_id}", response_model=List[RoleResponse])
def fetch_roles(company_id: int, db: Session = Depends(get_db)):
    roles = get_roles_by_company(company_id, db)
    return [
        {"RoleID": role.RoleID, "RoleName": role.RoleName, "PermissionLevel": role.PermissionLevel}
        for role in roles
    ]

@router.post("/roles", response_model=RoleResponse)
def create_role(role: RoleCreate, db: Session = Depends(get_db)):
    new_role = add_role(role.roleName, role.companyID, role.permissionLevel, db)
    return {
        "RoleID": new_role.RoleID,
        "RoleName": new_role.RoleName,
        "PermissionLevel": new_role.PermissionLevel,
    }

@router.delete("/roles/{role_id}", response_model=dict)
def remove_role(role_id: int, db: Session = Depends(get_db)):
    success = delete_role(role_id, db)
    if success:
        return {"message": "Role deleted successfully"}
    raise HTTPException(status_code=404, detail="Role not found")

@router.post("/upload-employees")
async def upload_employees(
    file: UploadFile = File(...), 
    companyID: int = Form(...),  # Changed to Form(...)
    db: Session = Depends(get_db)
):
    print(f"Received file: {file.filename}")
    print(f"Company ID: {companyID}")
    if not file:
        return JSONResponse(content={'message': 'No file provided.'}, status_code=400)

    try:
        # Read and decode the file contents
        contents = await file.read()
        contents = contents.decode('utf-8')  # Decode the file contents
        file_stream = StringIO(contents)  # Create a stream from the string
        
        print("Received file contents:")
        print(contents)  # Print the received CSV file contents
    except Exception as e:
        return JSONResponse(content={'message': f'Error reading file: {str(e)}'}, status_code=400)

    # Process the CSV file and populate the database
    try:
        # Call the function to populate roles and employees
        employees = populate_roles_and_employees(file_stream, companyID, db)

        # Print the response from populate_roles_and_employees
        print("Response from populate_roles_and_employees:")
        print(employees)

        # Prepare to send emails to each employee
        subject = "Your Company Account Credentials"

        print("Email list for employees:")
        # Loop through the employees to print their details and prepare for sending emails
        for employee in employees:
            print(f"{employee['name']} <{employee['email']}>")

        # Call the send_bulk_emails function with the employee list
        send_bulk_emails(employees, subject)

        return JSONResponse(content={'message': 'Employees uploaded and emails sent successfully.'}, status_code=200)
    
    except Exception as e:
        return JSONResponse(content={'message': f'Error processing file: {str(e)}'}, status_code=500)
    
@router.post("/employees", response_model=list)
async def get_employees(request: CompanyIDRequest, db: Session = Depends(get_db)):
    companyID = request.companyID  # Get companyID from the request body

    if not companyID:
        raise HTTPException(status_code=400, detail="Company ID is required")

    try:
        # Fetch employees along with their roles and managers in one query
        employees = db.query(Employees).options(
            joinedload(Employees.role),  # Load roles
            joinedload(Employees.manager)  # Load managers
        ).filter(Employees.CompanyID == companyID).all()

        # Prepare the employee list with required details
        employee_list = []
        for employee in employees:
            employee_list.append({
                'companyEmployeeID': employee.CompanyEmployeeID,
                'email': employee.Email,
                'name': employee.Name,
                'roleName': employee.role.RoleName if employee.role else 'Unknown Role',  # Access the role directly
                'manager': {
                    'companyEmployeeID': employee.manager.CompanyEmployeeID if employee.manager else None,
                    'name': employee.manager.Name if employee.manager else None
                } if employee.manager else None
            })

        return employee_list  # Return the prepared list of employees

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    
@router.post("/get-reimbursement-requests", response_model=list[ReimbursementRequestResponse])
async def get_reimbursement_requests(request: GetReimbursementRequestsRequest, db: Session = Depends(get_db)):
    try:
        company_id = request.companyID
        employee_id = request.employeeID

        # Check if both parameters are provided
        if not company_id or not employee_id:
            raise HTTPException(status_code=400, detail="companyID and employeeID are required")

        # Query the reimbursement requests table
        requests = db.query(ReimbursementRequest).filter_by(CompanyID=company_id, EmployeeID=employee_id).all()

        # Prepare the response data
        request_data = []
        for req in requests:
            request_data.append({
                'RequestID': req.RequestID,
                'EmployeeID': req.EmployeeID,
                'CompanyID': req.CompanyID,
                'ExpenseTypes': req.ExpenseTypes,
                'Amounts': req.Amounts,
                'TravelStartDate': req.TravelStartDate.isoformat(),
                'TravelEndDate': req.TravelEndDate.isoformat(),
                'Purpose': req.Purpose,
                'Description': req.Description,
                'Receipts': req.Receipts,
                'Status': req.Status,
                'SubmissionDate': req.SubmissionDate.isoformat()
            })

        return JSONResponse(content=request_data, status_code=200)

    except Exception as e:
        raise HTTPException(status_code=500, detail="An internal error occurred, please try again later.")

@router.post("/my-team-requests", response_model=list[ReimbursementRequestResponse])
async def get_my_team_requests(request: MyTeamRequestsRequest, db: Session = Depends(get_db)):
    employee_id = request.EmployeeID

    # Validate input
    if not employee_id:
        raise HTTPException(status_code=400, detail="Missing EmployeeID")

    try:
        # Fetch all employees reporting to the given EmployeeID
        underlings = db.query(Employees).filter(Employees.ManagerID == employee_id).all()
        if not underlings:
            raise HTTPException(status_code=404, detail="No underlings found for the given EmployeeID")

        # Extract underling EmployeeIDs
        underling_ids = [employee.EmployeeID for employee in underlings]

        # Fetch all requests for underlings in one query
        requests = db.query(ReimbursementRequest).filter(ReimbursementRequest.EmployeeID.in_(underling_ids)).all()
        if not requests:
            raise HTTPException(status_code=404, detail="No requests found for the underlings")

        # Map underling EmployeeIDs to their CompanyEmployeeIDs for quick lookup
        company_employee_map = {employee.EmployeeID: employee.CompanyEmployeeID for employee in underlings}

        # Transform requests into the response format
        response_data = [
            {
                "RequestID": req.RequestID,
                "EmployeeID": req.EmployeeID,
                "CompanyEmployeeID": company_employee_map.get(req.EmployeeID, "Unknown"),
                "CompanyID": req.CompanyID,
                "ExpenseTypes": req.ExpenseTypes,
                "Amounts": req.Amounts,
                "TravelStartDate": req.TravelStartDate.isoformat(),
                "TravelEndDate": req.TravelEndDate.isoformat(),
                "Purpose": req.Purpose,
                "Description": req.Description,
                "Receipts": req.Receipts or [],  # Default to an empty list if Receipts is missing
                "Status": req.Status,
                "SubmissionDate": req.SubmissionDate.isoformat(),
            }
            for req in requests
        ]

        return response_data

    except Exception as e:
        # Log the error for debugging
        print(f"Error in get_my_team_requests: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching team requests")

@router.post("/reimbursement-request", response_model=dict)
async def create_request(request_data: ReimbursementRequestCreate, db: Session = Depends(get_db)):
    try:
        # Insert the request into the database
        new_request = create_reimbursement_request(request_data.dict(), db)

        # Generate approval hierarchy
        approval_hierarchy = get_approval_hierarchy(request_data.EmployeeID, request_data.CompanyID, db)
        if not approval_hierarchy:
            raise HTTPException(status_code=500, detail="Failed to generate approval hierarchy")

        # Populate the ApprovalWorkflow table
        create_approval_workflow(new_request.RequestID, approval_hierarchy, db)

        return {
            "message": "Reimbursement request created successfully!",
            "RequestID": new_request.RequestID
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.post("/approve-reject")
async def approve_reject(data: ApproveRejectRequest, db: Session = Depends(get_db)):
    
    try:
        message, status_code = handle_approval_rejection(
            db, data.RequestID, data.Action, data.EmployeeID
        )
        return {"message": message}
    except HTTPException as e:
        raise e  # Propagate HTTP exceptions
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/test-email")
def test_email():
    """Test route to send a test email to multiple recipients."""
    recipients = [
        "dummy1@example.com",
        "shimmerarmy@gmail.com",
        "dummy2@example.com",
        "dummy3@example.com",
        "dummy4@example.com",
        "kaamalvn2311@gmail.com"
    ]

    subject = "Test Email from FastAPI"
    body_template = """
    <h1>This is a test email!</h1>
    <p>If you received this, the email functionality is working correctly.</p>
    <p>This email was sent to: {recipient}</p>
    """

    results = []

    for recipient in recipients:
        body = body_template.format(recipient=recipient)
        start_time = time.time()  # Start timing for each email
        try:
            send_email_duplicate(recipient, subject, body)
            duration = time.time() - start_time  # Calculate duration
            results.append({
                "recipient": recipient,
                "status": "success",
                "duration": f"{duration:.2f} seconds"
            })
        except Exception as e:
            duration = time.time() - start_time  # Calculate duration even if failed
            results.append({
                "recipient": recipient,
                "status": "failed",
                "error": str(e),
                "duration": f"{duration:.2f} seconds"
            })

    return {
        "results": results,
        "total_recipients": len(recipients)
    }
