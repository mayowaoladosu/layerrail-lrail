class HomeController < ApplicationController
  def show
    if rodauth.logged_in?
      redirect_to console_root_path
    else
      redirect_to rodauth.login_path
    end
  end
end
