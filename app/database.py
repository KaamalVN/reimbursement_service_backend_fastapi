import csv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import List
from .config import Config
from .models import Company, User, Role, Employees, ReimbursementRequest, ApprovalWorkflow  # Import Role model
from .utils import create_email_body, send_email, generate_random_password
from werkzeug.security import generate_password_hash
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
# Create the database engine
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)

# Create a session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Company-related functions
def insert_company(company_name: str, address: str, contact_email: str, db: Session):
    """Insert a new company into the database."""
    new_company = Company(
        CompanyName=company_name,
        Address=address,
        ContactEmail=contact_email
    )
    db.add(new_company)
    db.commit()
    db.refresh(new_company)
    return new_company.CompanyID

# User-related functions
def insert_user(db: Session, email: str, password_hash: str, role: str, company_id: int):
    """Insert a new user into the database."""
    new_user = User(
        Email=email,
        PasswordHash=password_hash,
        Role=role,
        CompanyID=company_id
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)  # Refresh the instance to get the updated state from the database
    return new_user

# Role-related functions
def get_roles_by_company(company_id: int, db: Session):
    """Fetch all roles associated with a specific company."""
    return db.query(Role).filter_by(CompanyID=company_id).all()

def add_role(role_name: str, company_id: int, permission_level: int, db: Session):
    """Add a new role to the database."""
    new_role = Role(
        RoleName=role_name,
        CompanyID=company_id,
        PermissionLevel=permission_level
    )
    db.add(new_role)
    db.commit()
    db.refresh(new_role)  # Refresh the instance to get the updated state from the database
    return new_role

def delete_role(role_id: int, db: Session):
    """Delete a role from the database by its ID."""
    role = db.query(Role).get(role_id)
    if role:
        db.delete(role)
        db.commit()
        return True
    return False

def populate_roles_and_employees(file_stream, company_id: int, db: Session):
    # Read CSV file
    reader = csv.DictReader(file_stream)
    role_name_to_role_id = {}
    roles_inserted = set()  # To avoid inserting duplicates
    employees = []  # Collect employee data for sending emails
    employee_id_to_company_id = {}

    # First Pass - Insert Users and Employees
    for row in reader:
        # Normalize keys by stripping spaces and converting to lowercase
        normalized_row = {key.strip().lower(): value for key, value in row.items()}
        
        employee_email = normalized_row['employeeemail']
        employee_password = generate_random_password(length=12) 
        password_hash = generate_password_hash(employee_password)  # Create a password hash

        new_user = User(
            Email=employee_email,
            PasswordHash=password_hash,
            Role='Employee',  # Set appropriate role or adjust as necessary
            CompanyID=company_id
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)  # Refresh the instance to get the updated state from the database

        # Store employee details for sending emails
        employees.append({
            'name': normalized_row['employeename'],
            'email': employee_email,
            'password': employee_password  # Store plain password before hashing
        })
        employee_id_to_company_id[normalized_row['companyemployeeid']] = new_user.UserID

    # Reset file stream for second pass
    file_stream.seek(0)
    reader = csv.DictReader(file_stream)

    # Second Pass - Insert Roles
    for row in reader:
        normalized_row = {key.strip().lower(): value for key, value in row.items()}
        
        role_name = normalized_row['rolename']  # Adjusted to lowercase
        permission_level = normalized_row['permissionlevel']  # Adjusted to lowercase
        
        if role_name not in roles_inserted:
            # Insert into Roles table
            new_role = Role(RoleName=role_name, CompanyID=company_id, PermissionLevel=permission_level)
            db.add(new_role)
            db.commit()
            db.refresh(new_role)  # Refresh the instance to get the updated state from the database
            role_name_to_role_id[role_name] = new_role.RoleID  # Store mapping
            roles_inserted.add(role_name)  # Mark this role as inserted

    # Reset file stream again for third pass
    file_stream.seek(0)  # Reset file stream for the third pass
    reader = csv.DictReader(file_stream)

    # Third Pass - Insert Employees and Update Manager IDs
    for row in reader:
        normalized_row = {key.strip().lower(): value for key, value in row.items()}  # Normalize again
        
        company_employee_id = normalized_row['companyemployeeid']  # Adjusted to lowercase
        name = normalized_row['employeename']  # Adjusted to lowercase
        email = normalized_row['employeeemail']  # Adjusted to lowercase
        role_id = role_name_to_role_id.get(normalized_row['rolename'])  # Get RoleID from mapping

        # Insert into Employees table without ManagerID
        new_employee = Employees(
            CompanyID=company_id,
            CompanyEmployeeID=company_employee_id,
            Name=name,
            Email=email,
            RoleID=role_id,
            ManagerID=None  # No manager ID initially
        )
        db.add(new_employee)
        db.commit()
        db.refresh(new_employee)  # Refresh the instance to get the updated state from the database
        employee_id_to_company_id[company_employee_id] = new_employee.EmployeeID
        # Store employee details for sending emails

    # Reset file stream again for fourth pass to update Manager IDs
    file_stream.seek(0)  # Reset file stream for the fourth pass
    reader = csv.DictReader(file_stream)
    print("Employee ID to Company ID mapping:", employee_id_to_company_id)  # Ensure we have the correct mapping

    try:
        for row in reader:
            normalized_row = {key.strip().lower(): value for key, value in row.items()}
            
            company_employee_id = normalized_row['companyemployeeid']  # Adjusted to lowercase
            manager_company_employee_id = normalized_row['managerid']  # Adjusted to lowercase
            
            logging.info(f"Processing employee: {company_employee_id}, Manager ID: {manager_company_employee_id}")
            
            if manager_company_employee_id:
                manager_employee_id = employee_id_to_company_id.get(manager_company_employee_id)
                
                if manager_employee_id:  # Check if manager exists in the mapping
                    # Use the session to query for the employee
                    employee_to_update = db.query(Employees).filter_by(CompanyEmployeeID=company_employee_id).first()
                    if employee_to_update:  # Check if the employee exists
                        employee_to_update.ManagerID = manager_employee_id
                        db.commit()  # Commit the change
                    else:
                        logging.warning(f"Employee not found for CompanyEmployeeID: {company_employee_id}")
                else:
                    logging.warning(f"Manager not found for CompanyEmployeeID: {manager_company_employee_id}")
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)




    # Return the collected employees for sending emails
    return employees

def get_requests_by_employee(employee_id: int, db: Session) -> list:
    try:
        # Get all request IDs for the given employee from the ApprovalWorkflow table
        request_ids = db.query(ApprovalWorkflow.RequestID).filter_by(ApproverID=employee_id).all()
        request_ids = [request_id[0] for request_id in request_ids]  # Extract the IDs from the tuples

        if not request_ids:
            return []  # No requests found

        # Get all reimbursement request details for those request IDs
        requests = db.query(ReimbursementRequest).filter(ReimbursementRequest.RequestID.in_(request_ids)).all()
        return requests
    except Exception as e:
        raise e  # Rethrow the exception for the calling function to handle

def get_previous_approver_status(request_id: int, employee_id: int, db: Session) -> bool: 
    # Fetch all approval workflows for the given request ID
    approvals = db.query(ApprovalWorkflow).filter_by(RequestID=request_id).order_by(ApprovalWorkflow.Sequence).all()
    print("Approvals fetched for RequestID {}: {}".format(request_id, approvals))

    # If there are no approvals found, this means this is the first approver
    if not approvals:
        print("No approvals found for RequestID {}, returning True".format(request_id))
        return True  # No previous approvers, so return True

    # Find the approval for the current employee
    current_approver = None
    for approval in approvals:
        print("Checking approval for ApproverID {}: {}".format(approval.ApproverID, approval.Status))
        if approval.ApproverID == employee_id:
            current_approver = approval
            break

    # If the employee is not found in the approvals, return False or handle as needed
    if current_approver is None:
        print("EmployeeID {} not found in approvals for RequestID {}, returning False".format(employee_id, request_id))
        return False

    # Check the sequence of the current approver
    if current_approver.Sequence == 1:
        print("ApproverID {} is the first approver for RequestID {}, returning True".format(employee_id, request_id))
        return True  # First approver always returns True

    # Check the previous approver's status
    previous_approver = approvals[current_approver.Sequence - 2]  # Get the previous approval
    print("Checking previous approver status for ApproverID {}: {}".format(previous_approver.ApproverID, previous_approver.Status))

    if previous_approver.Status == 'Approved':
        print("Previous approver (ID {}) has approved for RequestID {}, returning True".format(previous_approver.ApproverID, request_id))
        return True
    else:
        print("Previous approver (ID {}) has not approved for RequestID {}, returning False".format(previous_approver.ApproverID, request_id))
        return False  # Previous approver has not approved
    
def create_reimbursement_request(data: dict, db: Session) -> ReimbursementRequest:
    try:
        new_request = ReimbursementRequest(
            EmployeeID=data['EmployeeID'],
            CompanyID=data['CompanyID'],
            ExpenseTypes=data['ExpenseTypes'],
            Amounts=data['Amounts'],
            TravelStartDate=data['TravelStartDate'],
            TravelEndDate=data['TravelEndDate'],
            Purpose=data['Purpose'],
            Description=data['Description'],
            Receipts=data['Receipts']
        )
        db.add(new_request)
        db.commit()
        db.refresh(new_request)  # Refresh to get the new RequestID
        return new_request
    except Exception as e:
        db.rollback()
        raise e

def get_approval_hierarchy(employee_id: int, company_id: int, db: Session) -> List[tuple]:
    try:
        # Get the immediate manager of the employee
        employee = db.query(Employees).filter_by(EmployeeID=employee_id, CompanyID=company_id).first()
        if not employee:
            raise ValueError("Employee not found")

        manager_hierarchy = []
        current_manager_id = employee.ManagerID

        while current_manager_id:
            manager = db.query(Employees).filter_by(EmployeeID=current_manager_id, CompanyID=company_id).first()
            if not manager:
                break

            role = db.query(Role).filter_by(RoleID=manager.RoleID, CompanyID=company_id).first()
            if role:
                manager_hierarchy.append((manager.EmployeeID, role.PermissionLevel))

            current_manager_id = manager.ManagerID  # Move to the next manager in the hierarchy

        # Sort by PermissionLevel (ascending)
        manager_hierarchy.sort(key=lambda x: x[1])
        return manager_hierarchy
    except Exception as e:
        raise e

def create_approval_workflow(request_id: int, approval_hierarchy: List[tuple], db: Session):
    try:
        sequence = 1
        for approver_id, _ in approval_hierarchy:
            new_workflow = ApprovalWorkflow(
                RequestID=request_id,
                ApproverID=approver_id,
                Sequence=sequence,
                Status='Pending'
            )
            db.add(new_workflow)
            sequence += 1
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    
def handle_approval_rejection(db: Session, request_id: int, action: str, employee_id: int):
    # Fetch all workflows for the given request ID
    workflows = db.query(ApprovalWorkflow).filter_by(RequestID=request_id).all()

    # Check if there are any workflows
    if not workflows:
        return "No workflows found for the request ID", 404

    # Find the specific workflow for the employee ID
    current_workflow = None
    for workflow in workflows:
        if workflow.ApproverID == employee_id:
            current_workflow = workflow
            break

    # If no matching workflow found for the employee ID
    if not current_workflow:
        return "Employee is not an approver for this request", 403

    # Determine if this is the last approver
    is_last_approver = (current_workflow.Sequence == len(workflows))

    # Set the status based on the action value
    if action == "approve":
        current_workflow.Status = "Approved"
    elif action == "reject":
        current_workflow.Status = "Rejected"
    else:
        return "Invalid action specified", 400  # Handle invalid action

    # Commit the changes to the workflow
    db.commit()

    # If this is the last approver, update the request status as well
    if is_last_approver:
        reimbursement_request = db.query(ReimbursementRequest).get(request_id)
        if reimbursement_request:
            reimbursement_request.Status = current_workflow.Status  # Sync the request status with the workflow status
            db.commit()

    return "Request processed successfully", 200