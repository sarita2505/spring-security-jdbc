INSERT INTO users(username,password,enabled)
 VALUES('ram','ram','true');

 INSERT INTO users(username,password,enabled)
  VALUES('sita','sita','true');

  INSERT INTO authorities(username,authority)
   VALUES('ram','ROLE_ADMIN');

   INSERT INTO authorities(username,authority)
      VALUES('sita','ROLE_USER');