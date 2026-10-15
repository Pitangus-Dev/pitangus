class UsersController < ApplicationController
  def show
    # ruleid: appsec.rb.sql-interpolation
    User.where("name = '#{params[:name]}'")
    # ruleid: appsec.rb.command-injection
    system("ping #{params[:host]}")
    # ruleid: appsec.rb.unsafe-deserialization
    Marshal.load(params[:blob])
    # ruleid: appsec.rb.open-redirect
    redirect_to params[:next]
    # ruleid: appsec.rb.mass-assignment-permit-all
    params.permit!
    # ruleid: appsec.rb.html-safe-non-literal
    render html: params[:body].html_safe
  end

  # Safe counterparts: what the rules must leave alone.
  def safe
    # ok: appsec.rb.sql-interpolation
    User.where("name = ?", params[:name])
    # ok: appsec.rb.command-injection
    system("ls", "-l", params[:dir])
    # ok: appsec.rb.unsafe-deserialization
    YAML.safe_load(params[:doc])
    # ok: appsec.rb.html-safe-non-literal
    render html: "<b>fixed</b>".html_safe
    # ok: appsec.rb.mass-assignment-permit-all
    params.require(:user).permit(:name, :email)
    # ok: appsec.rb.open-redirect
    redirect_to root_path
  end
end
