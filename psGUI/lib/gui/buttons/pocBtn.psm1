## Control some buttons
Class pocBtns {
    $txtOutput
    $inpUserName
    $pswPassword

    ## Down and dirty button action as an "example" -- Don't use this for real...
    [void] btnPoc () {
        $ourUser = $this.inpUserName.Text
        $ourPass = $this.pswPassword.Text

        if ($ourUser -eq "") {
            Write-Host "Input a username"
            $this.txtOutput.Text = "Hey, put in a username"
        } else {
            Write-Host "Changing password for $ourUser`n"

            ## Uncomment below to actually change the password
            #net users $ourUser $ourPass
                        
            $this.txtOutput.Text += "Password successfully changed for $ourUser - maybe?"
        }

        ## Safety checks
        $this.inpUserName.Text = ""
    }
}