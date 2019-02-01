<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use App\Http\Requests;

use App\Models\User;
use App\Models\UserInterest;
use App\Models\Destination;

use Crypt;
use Hash;
use JWTFactory;
use JWTAuth;
use Mail;
use Response;

class UserController extends Controller
{
    public function authenticate(Request $request)
    {
        if ($request->has(['phoneNumber', 'password'])) 
        {
            $credentials = $request->only('phoneNumber', 'password');
        }
        else
        {
            $credentials = $request->only('email', 'password');
        }
        try 
        {
            if (! $token = JWTAuth::attempt($credentials)) 
            {
                return response()->json([
                    'status_code' => 401,
                    'message' => 'invalid credentials'
                ]);
            }
            $user = Auth::user();
            $user->remember_token = $token;
            $user->save();
        }
        catch (TokenExpiredException $e){
            // If the token is expired, then it will be refreshed and added to the headers
            try
            {
                $refreshed = JWTAuth::refresh(JWTAuth::getToken());
                $response->header('Authorization', 'Bearer ' . $refreshed);
            }
            catch (JWTException $e)
            {
                return ApiHelpers::ApiResponse(103, null);
            }
            $user = JWTAuth::setToken($refreshed)->toUser();
            $user->remember_token = $token;
            $user->save();
        }
        catch (JWTException $e)
        {
            return response()->json([
                'status_code' => 500,
                'message' => 'Couldn\'t create token'
            ]);
        }
       
          return response()->json([
                  'status_code' => 200,
                  'message' => 'user logged in successfully',
                  'user'  => Auth::user()
          ])->header('Authorization', $token);
    }

    public function logout()
    {
        JWTAuth::invalidate();
        return response()->json([
                'status_code' => 200,
                'message' => 'user logged out successfully'
        ]);
    }

    public function userRegistration(Request $request)
    {
        $existingUser=User::where('email',$request->email)
                        ->orWhere('phoneNumber',$request->phoneNumber)->get();

        if(count($existingUser) > 0)
        {
          return response()->json([
              'status_code' => 406,
              'message' => 'This user has registered before'
          ]);
        }

        $newUser=new User;
        $newUser->fullName=$request->fullName;
        $newUser->email=$request->email;
        $newUser->password = Hash::make($request->password);
        $newUser->phoneNumber=$request->phoneNumber;

        if ($request->profilePic)
        {
            $extension = $request->profilePic->getClientOriginalExtension();
            $fileSize = $request->profilePic->getClientSize();
            if ($fileSize > 15728640)
            {
                $file->resize(120,75);
            }

            $photoName = $request->email . time() . '.' . $extension;
            $destinationPath = base_path() . '/public/photo_uploads/usersPhoto';
            $request->profilePic->move($destinationPath, $photoName);
            $newUser->profilePic =$destinationPath.'/'.$photoName;
        }

        $result = $newUser->save();

        if (!$result) {
            return response()->json([
                'status_code' => 500,
                'message' => 'Failed Registration'
            ]);
        }
        else
        {
            $token = JWTAuth::fromUser($newUser);
        
            $originCode = mt_rand(1000,9999);
            $data = array(
            'email' => $request->email,
            'name' => $request->name,
            'code' => $originCode ,
            );
            $user = User::where('email',$request->email)->firstOrFail();
            $user->verifyCode = $originCode;
            $user->save();
            Mail::send('emails.registerUser', $data, function($message) use($data){
            $message->from('test@gmail.com');
            $message->to($data['email']);
            $message->subject('Test');
          });
            $newUser->profilePic  = substr($newUser->profilePic,14);
            return response()->json([
                'status_code' => 201,
                'message' => 'User Registered Successfully',
                'data'  => $newUser
            ])->header('Authorization', $token);
        }

    }

    public function verifyAccount(Request $request)
    {
        $user = User::where('email',$request->email)->firstOrFail();
        if($user)
        {
            if($user->verifyCode == $request->code)
            {
              $token = JWTAuth::fromUser($user);
              return response()->json([
                  'status_code' => 202,
                  'message' => 'User Verfied Successfully',
                ])->header('Authorization', $token);
            }
            else
            {
                return response()->json([
                  'status_code' => 400,
                  'message' => 'Wrong Code',
                ]);
            }
        }
        return response()->json([
            'status_code' => 404,
            'message' => 'User doesn\'t exist'
        ]);

    }

    public function forgetPassword(Request $request)
    {
        $user = User::where('email',$request->email)->firstOrFail();
        if($user)
        {
            $originCode = mt_rand(1000,9999);
            $data = array(
            'email' => $request->email,
            'code' => $originCode ,
            );
            $user->verifyCode = $originCode;
            $result = $user->save();
            if($result)
            {
              Mail::send('emails.forgetPassword', $data, function ($message) use($data){
                  $message->from('hello@app.com');
                  $message->to($data['email']);
                  $message->subject('Test');
              });
              return response()->json([
                  'status_code' => 200,
                  'message' => 'Sent code Successfully',
              ]);
            }  
            else
            {
              return response()->json([
                  'status_code' => 400,
                  'message' => 'Sent code Failed',
              ]);
            }
        }
        return response()->json([
            'status_code' => 404,
            'message' => 'User doesn\'t exist'
        ]);
    }

    public function resetPassword(Request $request)
    {
        $user = User::where('verifyCode',$request->code)->firstOrFail();
        if($user)
        {
            $token = JWTAuth::fromUser($user);
            $user->password = Hash::make($request->password);
            if($user->save())
            {
              return response()->json([
                  'status_code' => 205,
                  'message' => 'Update Password Successfully',
                ])->header('Authorization', $token);
            }
            else
            {
              return response()->json([
                  'status_code' => 400,
                  'message' => 'Not Save New Password',
                ]);
            }
        }
        return response()->json([
            'status_code' => 404,
            'message' => 'User doesn\'t exist'
        ]);
    }

    public function update(Request $request)
    {
      $user= Auth::user();

      if($user)
      {
        if ($request->profilePic)
        {
            $extension = $request->profilePic->getClientOriginalExtension();
            $fileSize = $request->profilePic->getClientSize();
            $photoName = Auth::user()->email . time() . '.' . $extension;
            $destinationPath = base_path() . '/public/photo_uploads/usersPhoto';
            $request->profilePic->move($destinationPath, $photoName);

            if($user->profilePic)
            {
              $image_path = $user->profilePic;
              unlink($image_path);
            }
            $user->profilePic = $destinationPath.'/'.$photoName;
        }

        if ($request->fullName)
        {
            $user->fullName = $request->fullName;
        }
        if ($request->password)
        {
            $user->password = Hash::make($request->password);
        }
        if ($request->phoneNumber)
        {
            $user->phoneNumber = $request->phoneNumber;
        }
        if ($request->NID)
        {
            $user->NID = $request->NID;
        }

        $result = $user->save();

        if ($result)
        {
            $user->profilePic  = substr($user->profilePic,14);
            return response()->json([
                'status_code' => 200,
                'message' => 'User Updated Successfully',
                'data'  => $user
            ]);
        }
        else
        {
          return response()->json([
              'status_code' => 500,
              'message' => 'Failed Update'
          ]);
        }
      }
      return response()->json([
          'status_code' => 404,
          'message' => 'User doesn\'t exist'
      ]);
    }
    public function delete(Request $request)
    {
        $userId= $request->id;
        $user= User::find($userId);

        if($user)
        {
            $destinationPath = base_path() . '/public/photo_uploads/usersPhoto';
            $image_path = $destinationPath.'/'.$user->profilePic;
            if(File::exists($image_path))
            {
                File::delete($image_path);
            }
            $user->delete();
            return response()->json([
                    'status_code' => 204,
                    'message' => 'User Deleted Successfully'
                ]);
        }
        return response()->json([
            'status_code' => 404,
            'message' => 'User doesn\'t exist'
        ]);
    }

    public function getUser(Request $request)
    {
      $userId= $request->id;
      $user= User::find($userId);
      if(!$user)
      {
        $user = User::all();
      }
      return response()->json([
              'status_code' => 200,
              'message' => 'User Retreived Successfully',
              'data'  => $user
          ]);
    }

    public function updateToken (Request $request)
    {
      $userId= $request->id;
      $user= User::find($userId);

      if($user)
      {
       	$user->remember_token = $request->token;
        $result = $user->save();
        if ($result)
        {
            return response()->json([
                'status_code' => 200,
                'message' => 'User Updated Successfully',
                'data'  => $user
            ]);
        }
        else
        {
          return response()->json([
              'status_code' => 500,
              'message' => 'Failed Update'
          ]);
        }
      }

      return response()->json([
          'status_code' => 404,
          'message' => 'User doesn\'t exist'
      ]);
    }

    public function updatePassword(Request $request)
    {
        $user = Auth::user();
        if($user)
        {    
            $oldPassword    = $request->oldPassword;
            $newPassword    = $request->newPassword;
            if($oldPassword == $newPassword)
            {
                return response()->json([
                      'status_code' => 500,
                      'message' => 'Failed Update'
                  ]);
            }
            $hashedPassword = Auth::user()->password;

            if (Hash::check($oldPassword, $hashedPassword)) 
            {
                $result = User::find(Auth::user()->id)
                    ->update(
                        ['password'=> Hash::make($newPassword)]
                    );

                if ($result)
                {
                    return response()->json([
                        'status_code' => 200,
                        'message' => 'Password Updated Successfully',
                        'data'  => $user
                    ]);
                }
                else
                {
                  return response()->json([
                      'status_code' => 500,
                      'message' => 'Failed Update'
                  ]);
                }
            }

          return response()->json([
              'status_code' => 404,
              'message' => 'Old Passowrd Wrong'
          ]);
        }
        return response()->json([
          'status_code' => 404,
          'message' => 'User doesn\'t exist'
      ]);
    }

}
