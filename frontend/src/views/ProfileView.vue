<script setup>
import PeerViewModal from "../components/PeerViewModal.vue";

import { computed, onMounted, ref } from "vue";
import { profileStore } from "@/stores/profile";
import { humanFileSize } from "@/helpers/utils";
import { settingsStore } from "@/stores/settings";
import { notify } from "@kyvg/vue3-notification";

const profile = profileStore()
const settings = settingsStore()

const viewedPeerId = ref("")

const sortKey = ref("")
const sortOrder = ref(1)
const selectAll = ref(false)
const isCreatingPeer = ref(false)

const maxPeersPerUser = computed(() => Number(settings.Setting("MaxPeersPerUser") || 0))
const canAddPeer = computed(() => maxPeersPerUser.value > profile.CountPeers)
const canShowAddPeer = computed(() => canAddPeer.value && profile.PeerInterfaces.length > 0)

function sortBy(key) {
  if (sortKey.value === key) {
    sortOrder.value = sortOrder.value * -1; // Toggle sort order
  } else {
    sortKey.value = key;
    sortOrder.value = 1; // Default to ascending
  }
  profile.sortKey = sortKey.value;
  profile.sortOrder = sortOrder.value;
}

function friendlyInterfaceName(id, name) {
  if (name) {
    return name
  }
  return id
}

function interfaceLabel(iface) {
  const name = friendlyInterfaceName(iface.Identifier, iface.DisplayName)
  if (name && name !== iface.Identifier) {
    return `${name} (${iface.Identifier})`
  }
  return iface.Identifier
}

async function addPeerOnInterface(interfaceId) {
  if (isCreatingPeer.value) return
  isCreatingPeer.value = true
  try {
    await profile.CreatePeer(interfaceId)
  } catch (e) {
    notify({
      title: "Failed to create peer!",
      text: e.toString(),
      type: "error",
    })
  } finally {
    isCreatingPeer.value = false
  }
}

function toggleSelectAll() {
  profile.FilteredAndPagedPeers.forEach(peer => {
    peer.IsSelected = selectAll.value;
  });
}

onMounted(async () => {
  await profile.LoadUser()
  await profile.LoadPeers()
  await profile.LoadPeerInterfaces()
  await profile.LoadStats()
  await profile.calculatePages(); // Forces to show initial page number
})

</script>

<template>
  <PeerViewModal :peerId="viewedPeerId" :visible="viewedPeerId !== ''" @close="viewedPeerId = ''"></PeerViewModal>

  <!-- Peer list -->
  <div class="mt-4 row">
    <div class="col-12 col-lg-5">
      <h2 class="mt-2">{{ $t('profile.headline') }}</h2>
    </div>
    <div class="col-12 col-lg-4 text-lg-end">
      <div class="form-group d-inline">
        <div class="input-group mb-3">
          <input v-model="profile.filter" class="form-control" :placeholder="$t('general.search.placeholder')" type="text"
            @keyup="profile.afterPageSizeChange">
          <button class="btn btn-primary" :title="$t('general.search.button')"><i
              class="fa-solid fa-search"></i></button>
        </div>
      </div>
    </div>
    <div class="col-12 col-lg-3 text-lg-end">
      <div v-if="canShowAddPeer" class="btn-group ms-2">
        <button class="btn btn-primary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false"
                :title="$t('profile.button-add-peer')" :disabled="isCreatingPeer">
          <i class="fa fa-plus"></i>
        </button>
        <ul class="dropdown-menu dropdown-menu-end">
          <li v-for="iface in profile.PeerInterfaces" :key="iface.Identifier">
            <a class="dropdown-item" href="#" @click.prevent="addPeerOnInterface(iface.Identifier)">{{ interfaceLabel(iface) }}</a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mt-2 table-responsive">
    <div v-if="profile.CountPeers === 0">
      <h4>{{ $t('profile.no-peer.headline') }}</h4>
      <p>{{ $t('profile.no-peer.abstract') }}</p>
    </div>
    <table v-if="profile.CountPeers !== 0" id="peerTable" class="table table-sm">
      <thead>
        <tr>
          <th scope="col">
            <input class="form-check-input" :title="$t('general.select-all')" type="checkbox" v-model="selectAll" @change="toggleSelectAll">
          </th><!-- select -->
          <th scope="col"></th><!-- status -->
          <th scope="col" @click="sortBy('DisplayName')">
            {{ $t("profile.table-heading.name") }}
            <i v-if="sortKey === 'DisplayName'" :class="sortOrder === 1 ? 'asc' : 'desc'"></i>
          </th>
          <th scope="col" @click="sortBy('Addresses')">
            {{ $t("profile.table-heading.ip") }}
            <i v-if="sortKey === 'Addresses'" :class="sortOrder === 1 ? 'asc' : 'desc'"></i>
          </th>
          <th v-if="profile.hasStatistics" scope="col" @click="sortBy('IsConnected')">
            {{ $t("profile.table-heading.stats") }}
            <i v-if="sortKey === 'IsConnected'" :class="sortOrder === 1 ? 'asc' : 'desc'"></i>
          </th>
          <th v-if="profile.hasStatistics" scope="col" @click="sortBy('Traffic')">RX/TX
            <i v-if="sortKey === 'Traffic'" :class="sortOrder === 1 ? 'asc' : 'desc'"></i>
          </th>
          <th scope="col">{{ $t('profile.table-heading.interface') }}</th>
          <th scope="col"></th><!-- Actions -->
        </tr>
      </thead>
      <tbody>
        <tr v-for="peer in profile.FilteredAndPagedPeers" :key="peer.Identifier">
          <th scope="row">
            <input class="form-check-input" type="checkbox" v-model="peer.IsSelected">
          </th>
          <td class="text-center">
            <span v-if="peer.Disabled" class="text-danger"><i class="fa fa-circle-xmark"
                :title="peer.DisabledReason"></i></span>
            <span v-if="!peer.Disabled && peer.ExpiresAt" class="text-warning"><i class="fas fa-hourglass-end"
                :title="peer.ExpiresAt"></i></span>
          </td>
          <td><span v-if="peer.DisplayName" :title="peer.Identifier">{{ peer.DisplayName }}</span><span v-else
              :title="peer.Identifier">{{ $filters.truncate(peer.Identifier, 10) }}</span></td>
          <td>
            <span v-for="ip in peer.Addresses" :key="ip" class="badge rounded-pill bg-light">{{ ip }}</span>
          </td>
          <td v-if="profile.hasStatistics">
            <div v-if="profile.Statistics(peer.Identifier).IsConnected">
              <span class="badge rounded-pill bg-success"><i class="fa-solid fa-link"></i></span>
              <span :title="profile.Statistics(peer.Identifier).LastHandshake">{{ $t('profile.peer-connected') }}</span>
            </div>
            <div v-else>
              <span class="badge rounded-pill bg-light"><i class="fa-solid fa-link-slash"></i></span>
            </div>
          </td>
          <td v-if="profile.hasStatistics" >
            <span class="text-center" >{{ humanFileSize(profile.Statistics(peer.Identifier).BytesReceived) }} / {{ humanFileSize(profile.Statistics(peer.Identifier).BytesTransmitted) }}</span>
          </td>
          <td>{{ peer.InterfaceIdentifier }}</td>
          <td class="text-center">
            <a href="#" :title="$t('profile.button-show-peer')" @click.prevent="viewedPeerId = peer.Identifier"><i
                class="fas fa-eye me-2"></i></a>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
  <hr>
  <div class="mt-3">
    <div class="row">
      <div class="col-6">
        <ul class="pagination pagination-sm">
          <li :class="{ disabled: profile.pageOffset === 0 }" class="page-item">
            <a class="page-link" @click="profile.previousPage">&laquo;</a>
          </li>

          <li v-for="page in profile.pages" :key="page" :class="{ active: profile.currentPage === page }" class="page-item">
            <a class="page-link" @click="profile.gotoPage(page)">{{ page }}</a>
          </li>

          <li :class="{ disabled: !profile.hasNextPage }" class="page-item">
            <a class="page-link" @click="profile.nextPage">&raquo;</a>
          </li>
        </ul>
      </div>
      <div class="col-6">
        <div class="form-group row">
          <label class="col-sm-6 col-form-label text-end" for="paginationSelector">
            {{ $t('general.pagination.size')}}:
          </label>
          <div class="col-sm-6">
            <select id="paginationSelector" v-model.number="profile.pageSize" class="form-select" @click="profile.afterPageSizeChange()">
              <option value="10">10</option>
              <option value="25">25</option>
              <option value="50">50</option>
            <option value="100">100</option>
            <option value="999999999">{{ $t('general.pagination.all') }}</option>
          </select>
        </div>
      </div>
    </div>
  </div>
</div></template>
