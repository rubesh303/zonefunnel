<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use App\User;
use DB;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\HasApiTokens;
use Illuminate\Notifications\Notifiable;
use Carbon\Carbon;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Password;
class RegisterController extends Controller
{
    
	use HasApiTokens;
	public static $rules = [
        'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
	];
    public function register(Request $request){
    	
    $users = User::where('email', $request->email)->get();
    # check if email is more than 1
    if(sizeof($users) > 0){
        return $this->errorResponse($message='This email already Exists!',$code = 400);
    }
    $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
    		]);
    $user->save();
         return $this->successResponse($user,$message='Successfully Registered!');    
    }

 public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);
        $credentials = request(['email', 'password']);
        if(!Auth::attempt($credentials))
            
        return $this->errorResponse($message='Unauthorized!',$code = 401);
        $user = $request->user();
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        if ($request->remember_me)
            $token->expires_at = Carbon::now()->addWeeks(1);
        $token->save();
        $data=array(
        	'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse(
                $tokenResult->token->expires_at
            )->toDateTimeString()
        );
       return $this->successResponse($data,$message='success'); 
    }

    public function forgot_password(Request $request)
{
    $input= $request->all();
    // echo $input['email'];
    // exit;
    $rules = array(
        'email' => "required|email",
    );
    $validator = Validator::make($input, $rules);
    if ($validator->fails()) {
        $arr = array("status" => 400, "message" => $validator->errors()->first(), "data" => array());
    } else {
        try {
            $response = Password::sendResetLink($request->only('email'), function (Message $message) {
                $message->subject("forgot password link");
            });
            switch ($response) {
                case Password::RESET_LINK_SENT:
                    return \Response::json(array("status" => 200, "message" => trans($response), "data" => array()));
                case Password::INVALID_USER:
                    return \Response::json(array("status" => 400, "message" => trans($response), "data" => array()));
            }
        } catch (\Swift_TransportException $ex) {
            $arr = array("status" => 400, "message" => $ex->getMessage(), "data" => []);
        } catch (Exception $ex) {
            $arr = array("status" => 400, "message" => $ex->getMessage(), "data" => []);
        }
    }
    return \Response::json($arr);
}
    protected function successResponse($data, $message = null, $code = 200)
	{
            // echo "<pre>";
            // print_r($data);
		return response()->json([
			'status'=> 'true', 
			'message' => $message, 
			'result' => $data
		], $code);
	}

    protected function errorResponse($message = null, $code = null)
	{
		return response()->json([
			'status'=> 'false', 
			'message' => $message
		], $code);
	}
}
