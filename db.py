import sys,os
import sqlite3





class apk_db():
    def __init__(self, db_name):
        self.db_name = db_name
        self.connection = sqlite3.connect(db_name)
        self.cursor = self.connection.cursor()
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")       
 
        if not self.cursor.fetchall():
            self.create_db(self.connection)

        
        
        



    def create_db(self,cursor):

        self.cursor.execute("""CREATE TABLE Application(sha256 TEXT, name TEXT, packageName TEXT, versionCode TEXT, 
                        versionName TEXT, minSdkVersion TEXT, targetSdkVersion TEXT, maxSdkVersion TEXT,
                        permissions TEXT, libraries TEXT, debuggable TEXT, allowbackup TEXT)""")
        self.cursor.execute("""CREATE TABLE Permissions(app_sha256 TEXT, permission TEXT, type TEXT, shortDescription TEXT, fullDescription TEXT)""")

        self.cursor.execute("""CREATE TABLE Activities(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, autoRemoveFromRecents TEXT, 
                        excludeFromRecents TRUE, noHistory TEXT, permission TEXT)""")

        self.cursor.execute("""CREATE TABLE Services(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, foregroundServiceType TEXT, permission TEXT, process TEXT)""")

        self.cursor.execute("""CREATE TABLE Providers(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, grantUriPermissions TEXT, permission TEXT, process TEXT, readPermission TEXT, writePermission TEXT, authorities TEXT)""")

        self.cursor.execute("""CREATE TABLE Receivers(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, permission TEXT, process TEXT)""")
        
        self.cursor.execute("""CREATE TABLE ActivityAlias(app_sha256 TEXT, name TEXT, enabled TEXT, exported TEXT, permission TEXT, targetActivity TEXT)""")

        self.cursor.execute("""CREATE TABLE IntentFilters(app_sha256 TEXT, componentName TEXT, actionList TEXT, categoryList TEXT, dataList TEXT)""")





    def query_db(self):
        #TODO
        return


    def update_intent_filters(self,attribs):
        sql = """INSERT INTO IntentFilters(app_sha256, componentName, actionList, categoryList, dataList) values(?,?,?,?,?)"""
        self.execute_query(sql,attribs)


    def update_application(self,attribs):
        sql = """INSERT INTO Application(sha256,name,packageName,versionCode,versionName,minSdkVersion,
        targetSdkVersion,maxSdkVersion,permissions,libraries, debuggable, allowbackup) values(?,?,?,?,?,?,?,?,?,?,?,?)"""
        self.execute_query(sql,attribs)

    def update_permissions(self,attribs):
        sql = """INSERT INTO Permissions(app_sha256,permission,type, shortDescription,fullDescription) values(?,?,?,?,?)"""
        self.execute_query(sql,attribs)

    def update_activities(self,attribs):
        sql = """INSERT INTO Activities(app_sha256, name, enabled, exported, autoRemoveFromRecents, 
                        excludeFromRecents, noHistory, permission) values(?,?,?,?,?,?,?,?)"""
        self.execute_query(sql,attribs)
    
    def update_services(self,attribs):
        sql = """INSERT INTO Services(app_sha256, name, enabled, exported, foregroundServiceType, 
                        permission, process) values(?,?,?,?,?,?,?)"""
        self.execute_query(sql,attribs)


    def update_providers(self,attribs):
        sql = """INSERT INTO Providers(app_sha256, name, enabled, exported, grantUriPermissions, 
                        permission, process,readPermission,writePermission,authorities) values(?,?,?,?,?,?,?,?,?,?)"""
        self.execute_query(sql,attribs)

    def update_receivers(self,attribs):
        sql = """INSERT INTO Receivers(app_sha256, name, enabled, exported, permission, process) values(?,?,?,?,?,?)"""
        self.execute_query(sql,attribs)
    
    def update_activity_alias(self,attribs):
        sql = """INSERT INTO ActivityAlias(app_sha256, name, enabled, exported, permission, targetActivity) values(?,?,?,?,?,?)"""
        self.execute_query(sql,attribs)






    def execute_query(self,sql,attribs):
        self.cursor.execute(sql,attribs)
        self.connection.commit()
        return








