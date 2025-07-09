#include <Arduino.h>
#include <LiquidCrystal.h>
 
LiquidCrystal lcd(7, 8, 9, 10, 11, 12);
String user;  
String password;      
String dump;
int attempts=0;
 
void setup() 
{
  Serial.begin(1200);   
  lcd.begin(16, 2);
  lcd.clear();
  lcd.setCursor(0, 0);    
  lcd.print("IoT Honeypot");
  lcd.setCursor(0, 1);
  lcd.print("h4k3rz incoming");  
}
 
void loop() 
{ 
    while (Serial.available()==0)
    {
      delay(100);
    }
    
    attempts++;
    lcd.clear();
    lcd.setCursor(0, 0);    
    lcd.print("hacker caught");
    lcd.setCursor(0, 1);
    lcd.print("Attempts:");
    lcd.print(attempts);  
    showBanner();
    getLogin();
    getPassword();
    //waitForInput();
    delay(350);    
    Serial.println("0919-0FF: INVALID CVV ENTRY / 0 OF 395 RECORDS RETURNED   ?REENTER\n");     
    
}
 
void showBanner()
{
  Serial.println(F("\n\n\n\n\n\n\n\n\n\n\n\n\n\nFDIC COLUMBIA SAVINGS AND LOAN CC PROC TELEHUB\n\n"));
  Serial.println(F("UNAUTHORIZED USE PROHIBITED BY LAW P.L. 81-797, 64 STAT. 783\n\n"));
  dump=Serial.readString();
}
 
void waitForInput()
{
  while (Serial.available()==0) {}
}
 
void getLogin()
{
  Serial.print(F("\nLOGIN: "));
  waitForInput();
  user=Serial.readString();
  user.trim();  
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("U:"+user);
}
 
void getPassword()
{
  Serial.print(F("PASSWORD: "));        
  waitForInput();
  password=Serial.readString();   
  password.trim(); 
  lcd.setCursor(0, 1);
  lcd.print("P:"+password);
}