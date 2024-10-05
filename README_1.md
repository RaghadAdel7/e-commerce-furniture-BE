# E-commerce Backend Project

## Project Overview

This is a comprehensive backend system solution for an e-commerce website that specializes in selling furniture. The system provide a managable infrastructure that deal with most aspects of the online e-commerce operations, such as product catalog managemnt, order processing..etc.


## Product Dsiplay Structure 
The back-end system features a multi-level product catalog that organizes the furniture inventory. At the top are broad product categories, such as Bedroom and Living Room.

Within each primary category, there are more granular subcategories. For example, the Bedroom category contains subcategories like Beds, Dressers, and Nightstands.

Housed under these subcategories are the individual product listings. So the Beds subcategory in Bedroom Category would include specific items like King Bed, Single Bed, and Kids bed, each with their own detailed information
(Categories -> Subcategories -> Individual Products).

This hierarchical structure allows customers to easily navigate the catalog, drill down into specific product types, and find the exact furniture pieces they need. The backend seamlessly manages this taxonomy of categories, subcategories, and individual products.




## Features

- **User Management**
  - Create new user
  - User authentication with JWT token
  - Role-based access control (Admin, Customer)
  - Display all users
  - Display specific user
  - Update user information
  - Check for user Username , Email and phone number 
  - Check null values
  - Delete specific user
 
- **Product Management**:
   - Products can be searched by its names. 
   - Products can be filtered based on price range , color , and product name.
   - Products can be sorted based on the added date (New Arrivals) , SKU (low stock) , and Price.
   - The search results highlight the products whose detailed descriptions best align with the user's search query.


- **Order Management**:
  - Create new order.
  - Retrieve all pending and completed orders included with pagination.
  - Update current order status along with its shipping date.
  - Cancel order depending in its status. 

- **SubCategory**
  - Search Subcategories with Pagination.
  - Retrieve all Products within a Subcategory.
  - Add/Update/Delete Products within a Subcategory.
  
- **Payment**
  - Adding a payment with active coupon(isActive: ture). 
  - Adding a payment with unactive coupon(isActive: false). (e.g. using outdated/wrong coupon)  

//cartDetails & the coupon will be written in the feature section


## Technologies Used

- **.Net 8**: Web API Framework
- **Entity Framework Core**: ORM for database interactions
- **PostgreSQl**: Relational database for storing data
- **JWT**: For user authentication and authorization
- **AutoMapper**: For object mapping
- **Swagger**: API documentation

## Prerequisites

- .Net 8 SDK
- SQL Server
- VSCode

## Getting Started

### 1. Clone the repository:

```bash
git clone https://github.com/your-username/e-commerce-backend.git
```

### 2. Setup database

- Make sure PostgreSQL Server is running
- Create `appsettings.json` file
- Update the connection string in `appsettings.json`

```json
{
  "ConnectionStrings": {
    "Local": "Server=localhost;Database=ECommerceDb;User Id=your_username;Password=your_password;"
  }
}
```

- Run migrations to create database

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

- Run the application

```bash
dotnet watch
```

The API will be available at: `http://localhost:5228`

### Swagger

- Navigate to `http://localhost:5228/swagger/index.html` to explore the API endpoints.

## Project structure

```bash
|-- Controllers # API controllers with request and response
|-- Database # DbContext and Database Configurations
|-- DTOs # Data Transfer Objects
|-- Entities # Database Entities (User, Product, Category, Order)
|-- Middleware # Logging request, response and Error Handler
|-- Repositories # Repository Layer for database operations
|-- Services # Business Logic Layer
|-- Utils # Common logics
|-- Migrations # Entity Framework Migrations
|-- Program.cs # Application Entry Point
```

## API Endpoints

### User

- **POST** `/api/v1/Users` – Creat a new user.
- **POST** `/api/v1/Users/signIn` – Login and get JWT token.
- **GET** `/api/v1/Users` - Display all users
- **GET** `/api/v1/Users/{id}` - Display specific user by Id
- **PUT** `/api/v1/Users/{id}` - Update user information by Id
- **DELETE** `api/v1/Users/{id}` - Delete user by Id

### Category

- **POST** `/api/v1/Categories` – Creat a new category.
- **GET** `/api/v1/Categories` - Retrieve all categories.
- **GET** `/api/v1/Categories/{id}` - Retrieve a specific category by its ID, including its details.
- **PUT** `/api/v1/Categories/{id}` - Update an existing category by its ID.
- **DELETE** `/api/v1/Categories/{id}` - Delete a category by its ID.

### Subcategory

- **POST** `/api/v1/SubCategories` – Creat a new subcategory.
- **POST** `/api/v1/SubCategories/{subCategoryId}/products` - Create and add a new product under a subcategory.
- **GET** `/api/v1/SubCategories` - Retrieve all subcategories.
- **GET** `/api/v1/SubCategories/{id}` - Retrieve a specific subcategory by its ID, including its details.
- **GET** `/api/v1/SubCategories/products` - Retrieve all products inside subcategories. 
- **GET** `/api/v1/SubCategories/products/{productId}` - Retrieve a specific product by its ID inside a subcategory.
 - **GET** `/api/v1/SubCategories/search` - Search for subcategories with pagination.
- **PUT** `/api/v1/SubCategories/{subCategoryId` - Update an existing subcategory by its ID.
- **PUT** `/api/v1/SubCategories/products/{productId}` - Update an existing product by its ID inside a subcategory.
- **DELETE** `/api/v1/SubCategories/{subCategoryId}` - Delete a subcategory by its ID.
- **DELETE** `/api/v1/SubCategories/products/{productId}` - Delete a product by its ID inside a subcategory.

#### Product
- **POST** `/api/v1/products` - Create new product.
- **GET** `/api/v1/products` - Get all products that matches the sort & filter & search query ,If no query provided, it will return all the products.
- **GET** `/api/v1/{productId}` - Get a specific product by id.
- **PUT** `/api/v1/products/{productId}` - Update product info by id.
- **DELETE** `/api/v1/products/{productId}` - Delete product info by id.


### Cart
 

### Payment

- **POST** `/api/v1/payments` - Create a new payment.
- **GET** `/api/v1/payments/{paymentId}` - Retrieve a specific payment by ID
- **POST** `/api/v1/payments `Create a new payment.
- **PUT** `/api/v1/payments/{paymentId}` - Update a payment by ID.
- **DELETE** `/api/v1/payments/{paymentId}` - Delete a payment by ID.

### Coupon
**POST** `/api/v1/coupons` - Create a new coupon.
**GET** `/api/v1/coupons` - Retrieve all coupons.
**GET** `/api/v1/coupons/{id}` - Retrive a specific coupon by ID.
**PUT** `/api/v1/coupons/{id}` - Update a coupon by ID.
**DELETE** `/api/v1/coupons/{id}` - Delete a coupon by ID.

### Order 
- **POST** `/api/v1/Orders/checkout` - Create a new order.
- **GET** `/api/v1/Orders` - Retrieve an specific order by ID.
- **GET** `/api/v1/Orders/{orderid}` - Retrieve all orders.
- **GET** `/api/v1/Orders/user/{userid}` - Retrieve all pending orders from a specific user ID.
- **GET** `/api/v1/Orders/user/{userid}/ordershistory` - Retrieve all delivered orders from a specific user ID.
- **PUT** `/api/v1/Orders/{orderid}` - Update an order by ID.
- **DELETE** `/api/v1/Orders/{orderid}` - Delete an order by ID.
### Review 


## Deployment

The application is deployed and can be accessed at: [https://your-deploy-link.com](https://your-deploy-link.com)

## Team Members

- **Leader** : Talal Alqarni (@TalalMAlqarni )
- **Member #1** : Abdulaziz Alsuhaibani (@ama47)
- **Member #2** : Jomana Mahjoob (@wbznan4)
- **Member #3** : Raghad Alessa (@RaghadAdel7)
- **Member #4** : Razan Altowairqi  (@razanmtw17)

## License

This project is licensed under the MIT License.
