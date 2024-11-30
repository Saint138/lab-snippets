from .example3_rpc_client import *
import argparse
import sys


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog=f'python -m snippets -l 4 -e 4',
        description='RPC client for user database',
        exit_on_error=False,
    )
    parser.add_argument('address', help='Server address in the form ip:port')
    parser.add_argument('command', help='Method to call', choices=['add', 'get', 'check', 'authenticate', 'validate_token'])
    parser.add_argument('--user', '-u', help='Username')
    parser.add_argument('--email', '--address', '-a', nargs='+', help='Email address')
    parser.add_argument('--name', '-n', help='Full name')
    parser.add_argument('--role', '-r', help='Role (defaults to "user")', choices=['admin', 'user'])
    parser.add_argument('--password', '-p', help='Password')
    parser.add_argument('--token', '-t', help='Token')
    parser.add_argument('--path', help='Path where to save/load the token file')

    if len(sys.argv) > 1:
        args = parser.parse_args()
    else:
        parser.print_help()
        sys.exit(0)

    args.address = address(args.address)
    user_db = RemoteUserDatabase(args.address)
    auth_service = RemoteAuthenticator(args.address) #creating an instance of RemoteAuthenticator


    try :
        ids = (args.email or []) + [args.user]
        if len(ids) == 0:
            raise ValueError("Username or email address is required")
        match args.command:
            case 'add':
                if not args.password:
                    raise ValueError("Password is required")
                if not args.name:
                    raise ValueError("Full name is required")
                user = User(args.user, args.email, args.name, Role[args.role.upper()], args.password)
                print(user_db.add_user(user)) #calling the add_user method
            case 'get':
                print(user_db.get_user(ids[0])) #calling the get_user method
            case 'check':
                credentials = Credentials(ids[0], args.password) #method for checking the password
                print(user_db.check_password(credentials)) #calling the check_password method

            case 'authenticate':
                credentials = Credentials(ids[0], args.password) # Only the first email is used
                token = auth_service.authenticate(credentials) #here we are calling the authenticate method
                if args.path: #if the path is provided, we save the token to the file
                    with open(args.path, 'w') as f: #open the file in write mode
                        f.write(serialize(token)) #write the token to the file
                print(token)

            case 'validate':
                if args.token and args.path: #if both token and path are provided, raise an error
                    raise ValueError("Provide either a token or a path, not both")
                if args.token: #if token is provided, use it
                    token = args.token #use the token
                elif args.path: #if path is provided, read the token from the file
                    with open(args.path, 'r') as file: #open the file in read mode
                        token = file.read().strip() #read the token from the file
                else:
                    raise ValueError("Either a token or a path to a token file is required")
                print(auth_service.validate_token(deserialize(token))) #calling the validate_token method
            case _:
                raise ValueError(f"Invalid command '{args.command}'")
    except RuntimeError as e:
        print(f'[{type(e).__name__}]', *e.args)
