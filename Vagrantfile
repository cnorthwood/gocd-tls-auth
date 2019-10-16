Vagrant.configure(2) do |config|
  config.vm.box = 'ubuntu/xenial64'

  config.vm.provider "virtualbox" do | vb |
    vb.memory = "4096"
  end

  config.vm.network 'forwarded_port', guest: 7443, host: 7443
  config.vm.network 'forwarded_port', guest: 8153, host: 8153

  config.vm.provision 'shell', inline: 'echo "deb https://download.gocd.org /" >/etc/apt/sources.list.d/gocd.list'
  config.vm.provision 'shell', inline: 'curl https://download.gocd.org/GOCD-GPG-KEY.asc | apt-key add -'
  config.vm.provision 'shell', inline: 'apt-get -y update'
  config.vm.provision 'shell', inline: 'apt-get -y install apache2 default-jdk go-agent go-server'
  config.vm.provision 'shell', inline: 'mkdir -p /var/lib/go-server/plugins/external/'
  config.vm.provision 'shell', inline: 'chown -R go:go /var/lib/go-server/'
  config.vm.provision 'shell', inline: 'test -L /var/lib/go-server/plugins/external/gocd-tls-auth-2.0.1.jar || ln -s /vagrant/target/gocd-tls-auth-2.0.1.jar /var/lib/go-server/plugins/external/'
  config.vm.provision 'shell', inline: 'test -f /vagrant/apache-config/key.pem || openssl req -x509 -newkey rsa:2048 -keyout /vagrant/apache-config/key.pem -out /vagrant/apache-config/cert.pem -days 30 -nodes -subj "/CN=localhost"'
  config.vm.provision 'shell', inline: 'test -L /etc/apache2/sites-enabled/gocd.conf || ln -s /vagrant/apache-config/httpd.conf /etc/apache2/sites-enabled/gocd.conf'
  config.vm.provision 'shell', inline: 'a2enmod proxy proxy_http ssl headers'
  config.vm.provision 'shell', inline: 'systemctl restart apache2.service'
  config.vm.provision 'shell', inline: 'systemctl start go-server.service'
  config.vm.provision 'shell', inline: 'systemctl start go-agent.service'
end
