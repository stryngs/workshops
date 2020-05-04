# psGUI
Create a GUI using PowerShell and Visual Studio

## theory
Do the heavy lifting in PowerShell and the Front-End GUI work with something nice like Visual Studio.  Let Visual Studio create the XAML, and then just point to it in the code.  Better yet, because we're not compiling, the end-result only needs the XAML.  You can store the Project folder elsewhere.  Copy the XAML(s) and go.  Combine this with Classing and you have everything you need to get started with bootstrapping this.

## useful
Use this as a framework for creating ever more complex GUI scenarios.  Do this all from the comfort of not having to know something like C# to get a GUI in Windows up and running.  Powershell + XAML == Fast and easy GUIs.

## creds
I built this workshop from tidbits I've picked up along the way in understanding PowerShell and how to effectively deploy it for those folks who might prefer a GUI as opposed to syntax.  Thanks to those who post gists and overflows.  3am runs rough on bookmarking that random URL that lead to success.

## Workshop environment prep
 - Visual Studio with the .NET desktop development installed
 - The Community Edition works perfect for this

## Word of warning
 - Read the code before you run it.  Understand and don't just copy the pasta.
 - GUIs present different dynamics than syntax driven ideas.
 - Users will click buttons.  Logic to stop/check unwanted repetition is needed.
