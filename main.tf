#Task 3

terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "5.25.0"
    }
  }
}

provider "google" {
  # Configuration options
project = "class5-5green"
credentials = "class5-5green-298b62a3188e.json"
}

resource "google_compute_network" "europehq_network" {
  name = "europehq-network"
  auto_create_subnetworks = false
  mtu = 1460
}


resource "google_compute_subnetwork" "europehq_subnet" {
  name = "europehq-subnet"
  network = google_compute_network.europehq_network.id
  ip_cidr_range = "10.102.21.0/24"
  region = "europe-central2"
  private_ip_google_access = true
}

resource "google_compute_firewall" "europehq_http" {
  name = "europehq-http"
  network = google_compute_network.europehq_network.id

  allow {
    protocol = "tcp"
    ports = ["80"]
  }
  source_ranges = ["10.102.21.0/24", "172.16.33.0/24", "172.19.29.0/24", "192.168.18.0/24"]
  target_tags = ["europehq-http-server", "americas-http-server", "asiapac-rdp-server"]
}

#Warsaw
resource "google_compute_instance" "europehq-vm" {
  name = "europehq-vm"  
  zone = "europe-central2-a"
  machine_type = "e2-medium"
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      }
  }

  metadata = {
    startup-script = "#Bbardzo dziękuję Remo!\n#!/bin/bash\n# Update and install Apache2\necho \"Running startup script. . .\"\napt update\napt install -y apache2\n\n# Start and enable Apache2\nsystemctl start apache2\nsystemctl enable apache2\n\n# GCP Metadata server base URL and header\nMETADATA_URL=\"http://metadata.google.internal/computeMetadata/v1\"\nMETADATA_FLAVOR_HEADER=\"Metadata-Flavor: Google\"\n\n# Use curl to fetch instance metadata\nlocal_ipv4=$(curl -H \"$${METADATA_FLAVOR_HEADER}\" -s \"$${METADATA_URL}/instance/network-interfaces/0/ip\")\nzone=$(curl -H \"$${METADATA_FLAVOR_HEADER}\" -s \"$${METADATA_URL}/instance/zone\")\nproject_id=$(curl -H \"$${METADATA_FLAVOR_HEADER}\" -s \"$${METADATA_URL}/project/project-id\")\nnetwork_tags=$(curl -H \"$${METADATA_FLAVOR_HEADER}\" -s \"$${METADATA_URL}/instance/tags\")\n\n# Create a simple HTML page and include instance details\ncat <<EOF > /var/www/html/index.html\n<html><body>\n<h2>Welcome to your custom website.</h2>\n<h3>Created with a direct input startup script!</h3>\n<p><b>Instance Name:</b> $(hostname -f)</p>\n<p><b>Instance Private IP Address: </b> $local_ipv4</p>\n<p><b>Zone: </b> $zone</p>\n<p><b>Project ID:</b> $project_id</p>\n<p><b>Network Tags:</b> $network_tags</p>\n</body></html>\nEOF"
  }

  service_account {
    scopes = ["cloud-platform"]
  }

  network_interface {
    network = google_compute_network.europehq_network.id
    subnetwork = google_compute_subnetwork.europehq_subnet.id
  }
  tags = ["europehq-http-server"]
}


resource "google_compute_network" "americas_network" {
  name = "americas-network"
  auto_create_subnetworks = false
  mtu = 1460
}

resource "google_compute_firewall" "americas_to_europehq_http" {
  name = "americas-to-europehq-http"
  network = google_compute_network.americas_network.id

  allow {
    protocol = "tcp"
    ports = ["22"]
  }
  source_ranges = ["0.0.0.0/0", "35.235.240.0/20"]
  target_tags = ["americas-http-server", "iap-ssh-allowed"]
}


resource "google_compute_subnetwork" "americas_01_subnet" {
  name = "americas-01-subnet"
  network = google_compute_network.americas_network.id
  ip_cidr_range = "172.16.33.0/24"
  region = "southamerica-east1"
  private_ip_google_access = true
}


resource "google_compute_subnetwork" "americas_02_subnet" {
  name = "americas-02-subnet"
  network = google_compute_network.americas_network.id
  ip_cidr_range = "172.19.29.0/24"
  region = "southamerica-west1"
  private_ip_google_access = true
}

#Sao Paulo
resource "google_compute_instance" "americas_01_vm" {
  name = "americas-01-vm"  
  zone = "southamerica-east1-a"
  machine_type = "e2-medium"
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      }
      mode = "READ_WRITE"      
  }
  labels = {
    google-ec-src = "americas"
  }

  network_interface {
    network = google_compute_network.americas_network.id
    subnetwork = google_compute_subnetwork.americas_01_subnet.id
    access_config {
    }
  }
  tags = ["americas-http-server", "iap-ssh-allowed"]
}

#Santiago
resource "google_compute_instance" "americas_02_vm" {
  name = "americas-02-vm"  
  zone = "southamerica-west1-a"
  machine_type = "e2-medium"
  boot_disk {
    auto_delete = true
    initialize_params {
      image = "debian-cloud/debian-12"
      }
      mode = "READ_WRITE"
  }
  labels = {
    google-ec-src = "americas"
  }

  network_interface {
    network = google_compute_network.americas_network.id
    subnetwork = google_compute_subnetwork.americas_02_subnet.id
    access_config {
      // Not assigned a public IP
    }
  }
  tags = ["americas-http-server", "iap-ssh-allowed"]
}


resource "google_compute_network_peering" "europehq_americas" {
  name = "europehq-americas-peering"
  network = google_compute_network.europehq_network.id
  peer_network = google_compute_network.americas_network.id
}

resource "google_compute_network_peering" "americas_europehq" {
  name = "americas-europehq-peering"
  network = google_compute_network.americas_network.id
  peer_network = google_compute_network.europehq_network.id
}


resource "google_compute_network" "asiapac_network" {
  name = "asiapac-network"
  auto_create_subnetworks = false
  mtu = 1460
}

resource "google_compute_firewall" "asiapac_allow_rdp" {
  name = "asiapac-allow-rdp"
  network = google_compute_network.asiapac_network.id

  allow {
    protocol = "tcp"
    ports = ["3389"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags = ["asiapac-rdp-server"] 
}

resource "google_compute_subnetwork" "asiapac_01_subnet" {
  name = "asiapac-01-subnet"
  network = google_compute_network.asiapac_network.id
  ip_cidr_range = "192.168.18.0/24"
  region = "asia-southeast1"
  private_ip_google_access = true
  }


#Singapore
resource "google_compute_instance" "asiapac_01_vm" {
  name = "asiapac-01-vm"  
  zone = "asia-southeast1-a"
  machine_type = "n2-standard-4"
  boot_disk {
    auto_delete = true
    initialize_params {
      image = "windows-cloud/windows-2019"
      }
      mode = "READ_WRITE"
  }
  labels = {
    google-ec-src = "asiapac"
  }

  network_interface {
    network = google_compute_network.asiapac_network.id
    subnetwork = google_compute_subnetwork.asiapac_01_subnet.id
    access_config {
      // Not assigned a public IP
    }
  }
  tags = ["asiapac-rdp-server"]
}

resource "google_compute_vpn_gateway" "europehq_vpn_gateway" {
  name = "europehq-vpn-gateway"
  network = google_compute_network.europehq_network.id
  region = "europe-central2"
}

resource "google_compute_vpn_gateway" "asiapac_vpn_gateway" {
  name = "asiapac-vpn-gateway"
  network = google_compute_network.asiapac_network.id
  region = "asia-southeast1"  
}

resource "google_compute_address" "europehq_vpn_ip" {
  name = "europehq-vpn-ip"
  region = "europe-central2"
}

resource "google_compute_address" "asiapac_vpn_ip" {
  name = "asiapac-vpn-ip"
  region = "asia-southeast1"
}

resource "google_compute_vpn_tunnel" "asiapac_to_europehq_tunnel" {
  name = "asiapac-to-europehq-tunnel"
  region = "asia-southeast1"
  peer_ip = google_compute_address.europehq_vpn_ip.address
  shared_secret = "mysecret"
  target_vpn_gateway = google_compute_vpn_gateway.asiapac_vpn_gateway.id
  ike_version = 2

local_traffic_selector = ["192.168.18.0/24"]
remote_traffic_selector = ["10.102.21.0/24"]

  depends_on = [
    google_compute_forwarding_rule.asiapac_esp,
    google_compute_forwarding_rule.asiapac_udp500,
    google_compute_forwarding_rule.asiapac_udp4500
  ]
}

resource "google_compute_route" "asiapac_to_europehq_route" {
  name = "asiapac-to-europehq-route"
  network = google_compute_network.asiapac_network.id
  dest_range = "10.102.21.0/24"
  next_hop_vpn_tunnel = google_compute_vpn_tunnel.asiapac_to_europehq_tunnel.id
  priority = 1000
} 

resource "google_compute_forwarding_rule" "asiapac_esp" {
  name = "asiapac-esp"
  region = "asia-southeast1"
  ip_protocol = "ESP"
  ip_address = google_compute_address.asiapac_vpn_ip.address
  target = google_compute_vpn_gateway.asiapac_vpn_gateway.self_link
}

resource "google_compute_forwarding_rule" "asiapac_udp500" {
  name = "asiapac-udp500"
  region = "asia-southeast1"
  ip_protocol = "UDP"
  port_range = "500"
  ip_address = google_compute_address.asiapac_vpn_ip.address
  target = google_compute_vpn_gateway.asiapac_vpn_gateway.self_link
}

resource "google_compute_forwarding_rule" "asiapac_udp4500" {
  name = "asiapac-udp4500"
  region = "asia-southeast1"
  ip_protocol = "UDP"
  port_range = "4500"
  ip_address = google_compute_address.asiapac_vpn_ip.address
  target = google_compute_vpn_gateway.asiapac_vpn_gateway.self_link
}

resource "google_compute_vpn_tunnel" "europehq_to_asiapac_tunnel" {
  name = "europehq-to-asiapac-tunnel"
  peer_ip = google_compute_address.asiapac_vpn_ip.address
  shared_secret = "mysecret"
  target_vpn_gateway = google_compute_vpn_gateway.europehq_vpn_gateway.id
  ike_version = 2

local_traffic_selector = ["10.102.21.0/24"]
remote_traffic_selector = ["192.168.18.0/24"]
  
    depends_on = [
      google_compute_forwarding_rule.europehq_esp,
      google_compute_forwarding_rule.europehq_udp500,
      google_compute_forwarding_rule.europehq_udp4500
    ]
  }

resource "google_compute_route" "europehq_to_asiapac_route" {
  depends_on = [google_compute_vpn_tunnel.europehq_to_asiapac_tunnel]
  name = "europehq-to-asiapac-route"
  network = google_compute_network.europehq_network.id
  dest_range = "192.168.18.0/24"
  next_hop_vpn_tunnel = google_compute_vpn_tunnel.europehq_to_asiapac_tunnel.id
}

resource "google_compute_forwarding_rule" "europehq_esp" {
  name = "europehq-esp"
  region = "europe-central2"
  ip_protocol = "ESP"
  ip_address = google_compute_address.europehq_vpn_ip.address
  target = google_compute_vpn_gateway.europehq_vpn_gateway.self_link
}

resource "google_compute_forwarding_rule" "europehq_udp500" {
  name = "europehq-udp500"
  region = "europe-central2"
  ip_protocol = "UDP"
  port_range = "500"
  ip_address = google_compute_address.europehq_vpn_ip.address
  target = google_compute_vpn_gateway.europehq_vpn_gateway.self_link
}

resource "google_compute_forwarding_rule" "europehq_udp4500" {
  name = "europehq-udp4500"
  region = "europe-central2"
  ip_protocol = "UDP"
  port_range = "4500"
  ip_address = google_compute_address.europehq_vpn_ip.address
  target = google_compute_vpn_gateway.europehq_vpn_gateway.self_link
}


output "europehq_vpn_ip_address" {
  value = google_compute_address.europehq_vpn_ip.address
}

output "asiapac_vpn_ip_address" {
  value = google_compute_address.asiapac_vpn_ip.address
}
 
 output "europehq_vm_internal_ip" {
  description = "Internal IP address of the Europe HQ VM"
  value = google_compute_instance.europehq-vm.network_interface[0].network_ip
}
 
#End of Task 3