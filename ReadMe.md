
# Library API

## Introduction
This library API utilizes a one-time use token for authenticated users, where tokens can only be used once with an expiry of 1 hour. The API has a total of 7 endpoints.

## How to test the API Endpoints
The **Thunder Client** allows for local testing of the Library API. To give it a try, you can do the following:  
1. Launch VS Code and open the **Thunder Client**.  
2. For the required endpoint, make a new request:  POST, GET, PUT, or DELETE are the possible methods.  This is the URL: `http://127.0.0.1/library/public/<endpoint>`  
**Body**: The user must supply the necessary JSON payload in the body for the functions `POST`, `PUT`, and `DELETE`. The one-time use token produced from a prior endpoint is also included in this. 
3. The HTTP header `Content-Type` must be set to `application/json` for endpoints.
  

## Endpoints
This section provides information on the API's URL, description, body, method, and sample replies, indicating if it was successful or not.
### User
#### /users/register
-  **URL**: `http://127.0.0.1/library/public/users/register`
-  **DESCRIPTION**: Registers a user to the database.
-  **Method**: POST
-  **Response**:
	```json
	{
		"username": "admin",
		"password": "admin123"
	}
	```
	- **Success**:
		```
		{
	  "status": "success",
		  "data": null
		}
		 ``` 
	 - **Fail**:
		```
		{
		  "status": "fail",
		  "data": "(error message generated from try-catch block)."
		}
		 ```

#### /user/authenticate
-  **URL**: `http://127.0.0.1/library/public/user/authenticate`
-  **DESCRIPTION**: Authenticates a registered user and provides the first token for the user to use.
-  **Method**: POST
-  **Response**:
	```json
	{
		"username": "admin",
		"password": "admin123"
	}
	```
	- **Success**:
		```
		{
	  "status": "success",
		 "token": "(generated token)"
		}
		 ``` 
	 - **Fail**:
		```
		{
		  "status": "fail",
		  "data": "Authentication Failed"
		}
		 ```

#### /user/update
-  **URL**: `http://127.0.0.1/library/public/user/update`
-  **DESCRIPTION**: Authenticates a registered user and provides the first token for the user to use.
-  **Method**: POST
-  **Response**:
	```json
	{
		"token" : "(insert token here)",
		"username": "admin",
		"password": "admin123"
	}
	```
	- **Success**:
		```
		{
	  "status": "success",
		 "token": "(generated token)"
		}
		 ``` 
	 - **Fail**:
		```
		{
		  "status": "fail",
		  "data": "Invalid Token or "
		}
		 ```

### Books
#### /books/add
-  **URL**: `http://127.0.0.1/library/public/books/add`
-  **DESCRIPTION**: Adds a new book with its title and author.
-  **Method**: POST
-  **Body**:
	```json
	{
		"title": "The Seventh Heaven",
		"authors": "Mia Handel",
		"token" : "(token here)"
	}
	```
- **Response**:
	- **Success**:
		```
		{
		  "status": "success",
		  "message": "Book added successfully.",
		  "token": (new generated token will appear here)
		}
		 ``` 
	 - **Fail**:
		```
		{
		  "status": "fail",
		  "data": "Invalid Token or"
		}
		 ```

#### /books/update
-  **URL**: `http://127.0.0.1/library/public/books/update`
-  **DESCRIPTION**: Updates a book by using its `bookid` as a main lookup.
-  **Method**: PUT
-  **Body**:
	```json
	{
		"token" : "(insert token here)",
		"bookid": 1,
		"title" : "After the Light",
		"authors" : "John Mason"
	}
	```
- **Response**:
	- **Success**:
		```
		{
		  "status": "success",
		  "message": "Book updated successfully."
		  "token": (generated token will appear here)
		}
		 ``` 
	 - **Fail**:
		```
		{
		  "status": "fail",
		  "data": "Invalid Token or"
		}
		 ```
		 
#### /books/delete
-  **URL**: `http://127.0.0.1/library/public/books/delete`
-  **DESCRIPTION**: Deletes a book by using the `bookid` on its payload.
-  **Method**: DELETE
-  **Body**:
	```json
	{
		"token" : "(insert token here)",
		"bookid": 1
	}
	```
- **Response**:
	- **Success**:
		```
		{
		  "status": "success",
		  "message": "Book deleted successfully."
		  "token": (generated token will appear here)
		}
		 ``` 
	 - **Fail**:
		```
		{
		  "status": "fail",
		  "data": "Invalid Token or"
		}
		 ```
		 
#### /books/list
-  **URL**: `http://127.0.0.1/library/public/books/list`
-  **DESCRIPTION**: Lists all the title of the books and its `bookid` in the library database.
-  **Method**: GET
-  **Response**:
	- **Success**:
		```
		{
		  "status": "success",
		  "books": [
		    {
		      "bookid": 1,
		      "title": "The Seventh Heaven",
		      "authors" : "Mia Handel"
		    }
		  ],
		  "token": "(generated token)"
		}
		 ``` 
	- **Fail**:
		```
		{
		  "status": "fail",
		  "data": "(error message generated from try-catch block)."
		}
		 ```