import datetime


class UserPlainAttribute:

    #NoneCriticalPersonalData flattened into SensitiveData, and UserPlainAttribute added to Administrator, 
    # Manager, and User for easier access to non-sensitive data.

    @property
    def first_name(self) -> str:
        return self.sensitive_data.non_critical_data.first_name
    
    @property
    def last_name(self) -> str:
        return self.sensitive_data.non_critical_data.last_name
    
    @property
    def second_last_name(self) -> str | None:
        return self.sensitive_data.non_critical_data.second_last_name
    
    @property
    def phone(self) -> str | None:
        return self.sensitive_data.non_critical_data.phone  
    
    @property
    def address(self) -> str | None:
        return self.sensitive_data.non_critical_data.address    
    
    @property
    def city(self) -> str | None:
        return self.sensitive_data.non_critical_data.city
    
    @property
    def state(self) -> str | None:
        return self.sensitive_data.non_critical_data.state
    
    @property
    def postal_code(self) -> str | None:
        return self.sensitive_data.non_critical_data.postal_code
    
    @property
    def birth_date(self) -> datetime.date | None:
        return self.sensitive_data.non_critical_data.birth_date
    
    
    # SensitiveData flattened into SensitiveData, and UserPlainAttribute added to Administrator, 
    # Manager, and User for easier access to non-sensitive data.

    @property
    def email(self) -> str:
        return self.sensitive_data.email   
    
    @property
    def password_hash(self) -> str:
        return self.sensitive_data.password_hash
    
    @property
    def curp(self) -> str | None:
        return self.sensitive_data.curp 
    
    @property
    def rfc(self) -> str | None:
        return self.sensitive_data.rfc  
    


