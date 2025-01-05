# OpenReportBackend
API server for OpenReport. Prevent spam, cheating, fraud and more in social web environments with OpenReport.

## Routers

### `/account` Router

This router handles account management functionality, such as registration, login, account deletion, and password reset.

#### Endpoints:

1. **POST `/register`**
   - **Body**:
     ```json
     {
       "userName": "string",
       "email": "string",
       "password": "string"
     }
     ```

2. **POST `/login`**
   - **Body**:
     ```json
     {
       "email": "string",
       "password": "string"
     }
     ```

3. **DELETE `/delete`**
   - **Body**:
     ```json
     {
       "id": "number",
       "password": "string"
     }
     ```

4. **POST `/reset-password-request`**
   - **Body**:
     ```json
     {
       "email": "string"
     }
     ```

5. **POST `/reset-password`**
   - **Body**:
     ```json
     {
       "token": "string",
       "newPassword": "string"
     }
     ```

6. **GET `/user/:id`**

---

### `/user-database` Router

This router manages user-specific database connections.

#### Endpoints:

1. **POST `/update`**
   - **Body**:
     ```json
     {
       "id": "number",
       "db_database": "string",
       "db_port": "number",
       "db_host": "string",
       "db_password": "string",
       "db_user_name": "string"
     }
     ```

---

### `/app` Router

This router manages user-created applications.

#### Endpoints:

1. **POST `/create`**
   - **Body**:
     ```json
     {
       "id": "number",
       "appName": "string",
       "domains": ["string"]
     }
     ```

2. **PATCH `/update-thresholds`**
   - **Body**:
     ```json
     {
       "id": "number",
       "appId": "number",
       "warnlistThreshold": "number",
       "blacklistThreshold": "number"
     }
     ```

3. **DELETE `/delete`**
   - **Body**:
     ```json
     {
       "id": "number",
       "appId": "number"
     }
     ```

4. **GET `/apps/:id`**
   - Returns all apps belonging to or moderated by the user.
   - **No Body Required**.

5. **PUT `/update-domains`**
- **Body**:
  ```json
  {
    "id": "number",
    "appId": "number",
    "domains": ["string"]
  }
  ```

6. **PUT `/app-secret`**
- **Body**:
  ```json
  {
    "id": "number",
    "appId": "number"
  }
  ```

---

### `/moderator` Router

This router manages application moderators.

#### Endpoints:

1. **POST `/add`**
   - **Body**:
     ```json
     {
       "id": "number",
       "appId": "number",
       "email": "string"
     }
     ```

2. **DELETE `/remove`**
   - **Body**:
     ```json
     {
       "id": "number",
       "appId": "number",
       "email": "string"
     }
     ```

3. **PUT `/moderators`**
   - **Body**:
     ```json
     {
       "id": "number",
       "appId": "number"
     }
     ```

---

### `/report` Router

This router handles reporting functionalities for apps, including submission, deletion, manual additions, cleaning, and retrieving entries.

#### Endpoints:

1. **POST `/submit`**
   - **Description**: Submit a report for a specific app.
   - **Body**:
     ```json
     {
       "key": "string",
       "referenceId": "string",
       "type": "string",
       "reason": "string",
       "notes": "string",
       "link": "string"
     }
     ```

2. **DELETE `/delete`**
   - **Description**: Delete an entry from the reports, blacklist, or warnlist of a specific app.
   - **Body**:
     ```json
     {
       "id": "number",
       "appId": "number",
       "table": "string",
       "entryId": "number"
     }
     ```

3. **POST `/add-manually`**
   - **Description**: Manually add an entry to the blacklist or warnlist of a specific app.
   - **Body**:
     ```json
     {
       "id": "number",
       "appId": "number",
       "table": "string",
       "referenceId": "string",
       "type": "string",
       "reason": "string",
       "link": "string"
     }
     ```

4. **DELETE `/clean`**
   - **Description**: Clean old entries from the reports, blacklist, or warnlist of a specific app based on age.
   - **Body**:
     ```json
     {
       "id": "number",
       "appId": "number",
       "days": "number",
       "table": "string"
     }
     ```

5. **PUT `/get-table`**
   - **Description**: Retrieve entries from the reports, blacklist, or warnlist of a specific app with pagination. The search query is optional.
   - **Body**:
    ```json
    {
     "id": "number",
     "appId": "number",
     "table": "string",
     "page": "number",
     "search": "string"
    }
     ```

5. **PUT `/get-table`**
   - **Description**: Retrieve entries from the reports, blacklist, or warnlist of a specific app with pagination.
   - **Body**:
    ```json
    {
     "appId": "number",
     "table": "string",
     "referenceId": "string",
     "secret": "string"
    }
     ```

---

**### `/subscription` Router**
This router handles subscription management through Stripe.
**#### Endpoints:**
1. **POST `/create-checkout-session`**
- **Body**:
```json
{
    "id": "number",
    "lookup_key": "string"
}
```
2. **POST `/create-portal-session`**
- **Body**:
```json
{
    "id": "number"
}
```
3. **POST `/webhook`**
- **Body**: Raw Stripe webhook payload
- **Headers**:
```json
{
    "stripe-signature": "string"
}
```
---

## MySQL Database Setup

The application uses several tables to store user, app, and moderation-related data.

### Tables

#### `users`
| Column             | Type         | Nullable | Key        | Additional Info            |
|--------------------|--------------|----------|------------|----------------------------|
| id                 | INT          | NO       | PRIMARY    | AUTO_INCREMENT             |
| created_at         | DATETIME(6)  | YES      |            |                            |
| email              | VARCHAR(255) | YES      | UNIQUE     | Consider indexing this     |
| password           | VARCHAR(255) | YES      |            |                            |
| user_name          | VARCHAR(255) | NO       |            |                            |
| report_limit       | INT          | NO       |            |                            |
| moderator_limit    | INT          | NO       |            |                            |
| stripe_customer_id | VARCHAR(255) | NO       |            |                            |
| subscription_tier  | INT          | NO       |            |                            |

#### `users_databases`
| Column       | Type         | Nullable | Key        | Additional Info            |
|--------------|--------------|----------|------------|----------------------------|
| id           | INT          | NO       | PRIMARY    | AUTO_INCREMENT             |
| user_id      | INT          | NO       | FOREIGN    | FOREIGN KEY (CASCADE, CASCADE) REFERENCES `users(id)` |
| db_database  | VARCHAR(255) | NO       |            |                            |
| db_port      | INT          | NO       |            |                            |
| db_host      | VARCHAR(255) | NO       |            |                            |
| db_password  | VARCHAR(255) | NO       |            |                            |
| db_user_name | VARCHAR(255) | NO       |            |                            |

#### `users_apps`
| Column               | Type         | Nullable | Key        | Additional Info            |
|----------------------|--------------|----------|------------|----------------------------|
| id                   | INT          | NO       | PRIMARY    | AUTO_INCREMENT             |
| creator_id           | INT          | NO       | FOREIGN    | FOREIGN KEY (CASCADE, CASCADE) REFERENCES `users(id)` |
| app_name             | VARCHAR(255) | NO       | UNIQUE     | Consider indexing this     |
| warnlist_threshold   | INT          | NO       |            | DEFAULT 5                  |
| blacklist_threshold  | INT          | NO       |            | DEFAULT 10                 |
| moderator_count      | INT          | NO       |            |                            |
| api_key              | VARCHAR(255) | NO       |            |                            |
| secret_key           | VARCHAR(255) | NO       |            |                            |

#### `users_apps_domains`
| Column  | Type         | Nullable | Key        | Additional Info                           |
|---------|--------------|----------|------------|-------------------------------------------|
| id      | INT          | NO       | PRIMARY    | AUTO_INCREMENT                            |
| app_id  | INT          | NO       | FOREIGN    | FOREIGN KEY (CASCADE, CASCADE) REFERENCES `users_apps(id)` |
| domain  | VARCHAR(255) | NO       |            |                                           |

#### `apps_moderators`
| Column  | Type         | Nullable | Key        | Additional Info                           |
|---------|--------------|----------|------------|-------------------------------------------|
| id      | INT          | NO       | PRIMARY    | AUTO_INCREMENT                            |
| app_id  | INT          | NO       | FOREIGN    | FOREIGN KEY (CASCADE, CASCADE) REFERENCES `users_apps(id)` |
| user_id | INT          | NO       |            | Consider indexing this                   |

---

### Recommendations

1. **Indexing**:
   - Index the `email` and `stripe_customer_id` columns in the `users` table for faster lookups.
   - Index the `app_name`, `api_key` and `secret_key` columns in the `users_apps` table to improve performance.
   - Index the `user_id` column in the `apps_moderators` table for efficient queries.

2. **Foreign Key Constraints**:
   - Ensure all foreign keys are set to `ON DELETE CASCADE` and `ON UPDATE CASCADE`.