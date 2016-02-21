Vagrant.configure(2) do |config|
  config.vm.box = 'gocd/gocd-demo'

  config.vm.network 'forwarded_port', guest: 7443, host: 7443

  config.vm.provision 'shell', inline: 'apt-get install apache2'
  config.vm.provision 'shell', inline: 'test -L /var/lib/go-server/plugins/external/gocd-tls-auth-1.0.jar || ln -s /vagrant/target/gocd-tls-auth-1.0.jar /var/lib/go-server/plugins/external/'
  config.vm.provision 'shell', inline: 'test -f /vagrant/apache-config/key.pem || openssl req -x509 -newkey rsa:2048 -keyout /vagrant/apache-config/key.pem -out /vagrant/apache-config/cert.pem -days 30 -nodes -subj "/CN=localhost"'
  config.vm.provision 'shell', inline: 'test -L /etc/apache2/sites-enabled/gocd.conf || ln -s /vagrant/apache-config/httpd.conf /etc/apache2/sites-enabled/gocd.conf'
  config.vm.provision 'shell', inline: 'a2enmod proxy proxy_http ssl headers'
  config.vm.provision 'shell', inline: 'service apache2 restart'
end
