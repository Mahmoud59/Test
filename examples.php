<?php
// example of notification
$user->notify(new \App\Notifications\PostNotification($postStatus,$user->id));


// example of email
Mail::send('emails.forgetPassword', $data, function ($message) use($data){
                  $message->from('hello@app.com');
                  $message->to($data['email']);
                  $message->subject('Test');
              });


// example of SMS
Mail::send('emails.test',['name'=>'Novica'],function($message)
{
    $message->to('ttwo59@yahoo.com','some test')->from('test@yahoo.com')->subject(
        'welcome');
});





?>