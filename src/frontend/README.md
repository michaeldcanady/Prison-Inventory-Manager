# Frontend Service

The frontend service manages the user-facing web interface for the application.

Implemented in Python with Flask.

### Endpoints

| Endpoint  | Type | Auth? | Description                                                                        |
| --------- | ---- | ----- | ---------------------------------------------------------------------------------- |
| `/`       | GET  | 🔒    | Renders `/home` or `/login` based on authentication status. Must always return 200 |
| `/home`   | GET  | 🔒    | Renders homepage if authenticated Otherwise redirects to `/login`                  |
| `/login`  | GET  |       | Renders login page if not authenticated. Otherwise redirects to `/home`            |
| `/login`  | POST |       | Submits login request to `userservice`                                             |
| `/logout` | POST | 🔒    | delete local authentication token and redirect to `/login`                         |
| `/signup` | GET  |       | Renders signup page if not authenticated. Otherwise redirects to `/home`           |
| `/signup` | POST |       | Submits new user signup request to `userservice`                                   |

### Environment Variables

- `VERSION` - a version string for the service
- `PORT` - the port for the webserver
- `SCHEME` - the URL scheme to use on redirects (http or https)
- `DEFAULT_USERNAME` - a string to pre-populate the "username" field. Optional
- `DEFAULT_PASSWORD` - a string to pre-populate the "password" field. Optional
- `APP_NAME` - a string that will be shown in the navbar to indicate the name of the bank. Optional, defaults to `Prison Inventory Manager`
