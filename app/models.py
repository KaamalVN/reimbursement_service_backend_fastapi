from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, JSON, Text
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
from werkzeug.security import check_password_hash

Base = declarative_base()

class Company(Base):
    __tablename__ = 'companies'
    CompanyID = Column(Integer, primary_key=True)
    CompanyName = Column(String(100), nullable=False)
    Address = Column(String(200), nullable=False)
    ContactEmail = Column(String(100), nullable=False)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = 'users'
    UserID = Column(Integer, primary_key=True)
    Email = Column(String(100), nullable=False, unique=True)
    PasswordHash = Column(String(200), nullable=False)
    Role = Column(String(50), nullable=False)
    CompanyID = Column(Integer, ForeignKey('companies.CompanyID'), nullable=False)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, onupdate=datetime.utcnow)
    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.PasswordHash, password)

class Role(Base):
    __tablename__ = 'roles'
    RoleID = Column(Integer, primary_key=True, autoincrement=True)
    RoleName = Column(String(255), nullable=False)
    CompanyID = Column(Integer, nullable=False)
    PermissionLevel = Column(Integer, nullable=False)

class Employees(Base):
    __tablename__ = 'employees'
    EmployeeID = Column(Integer, primary_key=True)
    CompanyID = Column(Integer, ForeignKey('companies.CompanyID'), nullable=False)
    CompanyEmployeeID = Column(String(50), nullable=False)
    Name = Column(String(100), nullable=False)
    Email = Column(String(100), nullable=False)
    RoleID = Column(Integer, ForeignKey('roles.RoleID'), nullable=False)
    ManagerID = Column(Integer, ForeignKey('employees.EmployeeID'))

    # Define relationships
    manager = relationship('Employees', remote_side=[EmployeeID], backref='subordinates')
    role = relationship('Role')

class ReimbursementRequest(Base):
    __tablename__ = 'reimbursementrequests'
    RequestID = Column(Integer, primary_key=True, autoincrement=True)
    EmployeeID = Column(Integer, ForeignKey('employees.EmployeeID'), nullable=False)
    CompanyID = Column(Integer, ForeignKey('companies.CompanyID'), nullable=False)
    ExpenseTypes = Column(JSON, nullable=False)
    Amounts = Column(JSON, nullable=False)
    TravelStartDate = Column(DateTime, nullable=False)
    TravelEndDate = Column(DateTime, nullable=False)
    Purpose = Column(Text, nullable=False)
    Description = Column(String(255), nullable=False)
    Receipts = Column(JSON, nullable=True)
    Status = Column(String(50), default='Pending')
    SubmissionDate = Column(DateTime, default=datetime.utcnow)

class ApprovalWorkflow(Base):
    __tablename__ = 'approvalworkflow'
    WorkflowID = Column(Integer, primary_key=True, autoincrement=True)
    RequestID = Column(Integer, ForeignKey('reimbursementrequests.RequestID'), nullable=False)
    ApproverID = Column(Integer, ForeignKey('employees.EmployeeID'), nullable=False)
    Sequence = Column(Integer, nullable=False)
    Status = Column(String(50), default='Pending')
    ApprovalDate = Column(DateTime, nullable=True)
